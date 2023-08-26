require "base64"
require "socket"
require "openssl"
require "yajl"
require "zlib"
require "date"
require "fluent/plugin/output"
require 'digest'
require 'json'

class Fluent::Site24x7Output < Fluent::Plugin::Output
  
  Fluent::Plugin.register_output('site24x7', self)
  
  S247_MAX_RECORD_COUNT = 500
  S247_MAX_RECORD_SIZE = 1000000
  S247_MAX_BATCH_SIZE = 5000000
  S247_LOG_UPLOAD_CHECK_INTERVAL = 600 #10 minutes
  S247_TRUNCATION_SUFFIX = "##TRUNCATED###"

  helpers :compat_parameters

  config_param :log_type_config, :string
  config_param :max_retry, :integer, :default => -1
  config_param :retry_interval, :integer, :default => 2
  config_param :maxretry_interval, :integer, :default => 60 #1 minutes 
  config_param :retry_timeout, :integer, :default => 24 * 3600  # 24 hours
  config_param :http_idle_timeout, :integer, default: 5
  config_param :http_read_timeout, :integer, default: 30
  config_param :http_proxy, :string, :default => nil

  config_section :buffer do
    config_set_default :@type, "memory"
  end

  def initialize
    super
  end

  def configure(conf)
    compat_parameters_convert(conf, :buffer)
    super
    if conf['http_proxy']
        ENV['http_proxy'] = @http_proxy
    end
  end

  def multi_workers_ready?
    true
  end

  def formatted_to_msgpack_binary?
    true
  end

  def start
    super
    init_variables()
    init_http_client(@logtype_config)
  end

  def shutdown
    super
  end

  def terminate
    super
    @s247_http_client.shutdown if @s247_http_client
  end

  def base64_url_decode(str)
     str += '=' * (4 - str.length.modulo(4))
     Base64.decode64(str.tr('-_','+/'))
  end
  
  def init_variables()
    @logtype_config = Yajl::Parser.parse(base64_url_decode(@log_type_config))
    @s247_custom_regex = if @logtype_config.has_key? 'regex' then Regexp.compile(@logtype_config['regex'].gsub('?P<','?<')) else nil end
    @s247_ignored_fields = if @logtype_config.has_key? 'ignored_fields' then @logtype_config['ignored_fields'] else [] end
    @datetime_regex = if @logtype_config.has_key?'dateRegex' then Regexp.compile(@logtype_config['dateRegex'].gsub('?P<','?<')) else nil end

    @ml_regex = if @logtype_config.has_key? 'ml_regex' then Regexp.compile(@logtype_config['ml_regex'].gsub('?P<','?<')) else nil end
    @ml_end_regex = if @logtype_config.has_key? 'ml_end_regex' then Regexp.compile(@logtype_config['ml_end_regex'].gsub('?P<','?<')) else nil end
    @max_ml_count = if @logtype_config.has_key? 'ml_regex' then @s247_custom_regex.inspect.scan('\<NewLine\>').length else nil end
    @max_trace_line = 100
    @ml_trace = ''
    @ml_trace_buffer = ''
    @ml_found = false
    @ml_end_line_found = false
    @ml_data = nil
    @ml_count = 0
    
    @json_data = ''
    @sub_pattern = {}

    if !(@logtype_config.has_key?('jsonPath'))
      @message_key = get_last_group_inregex(@s247_custom_regex)
    end
    
    if @logtype_config.has_key?('jsonPath')
      @logtype_config['jsonPath'].each_with_index do | key, index |
        if key.has_key?('pattern')
          begin
            if Regexp.new(key['pattern'].gsub('?P<','?<'))
              @sub_pattern[key['name']] = Regexp.compile(key['pattern'].gsub('?P<','?<'))
            end
          rescue Exception => e
            log.error "Invalid subpattern regex #{e.backtrace}"
          end
        end
      end 
    end

    @old_formatted_line = {}
    @formatted_line = {}

    @masking_config = if @logtype_config.has_key? 'maskingConfig' then  @logtype_config['maskingConfig']  else nil end
    @hashing_config = if @logtype_config.has_key? 'hashingConfig' then  @logtype_config['hashingConfig']  else nil end
    @derived_config = if @logtype_config.has_key? 'derivedConfig' then @logtype_config['derivedConfig'] else nil end
    @general_regex = Regexp.compile("(.*)")
    
    if @derived_config
      @derived_fields = {}
      for key,value in @derived_config do
        @derived_fields[key] = []
        for values in @derived_config[key] do
          @derived_fields[key].push(Regexp.compile(values.gsub('\\\\', '\\')))
        end
      end
    end
    
    if @masking_config
      for key,value in @masking_config do
        @masking_config[key]["regex"] = Regexp.compile(@masking_config[key]["regex"])
      end
    end
    
    if @hashing_config
      for key,value in @hashing_config do
        @hashing_config[key]["regex"] = Regexp.compile(@hashing_config[key]["regex"])
      end
    end

    if @logtype_config.has_key?'filterConfig'
      for field,rules in @logtype_config['filterConfig'] do
        temp = []
        for value in @logtype_config['filterConfig'][field]['values'] do
          if @logtype_config['filterConfig'][field]['exact']
            temp.push("\\A"+value+"\\Z")
          else
            temp.push(value)
          end
        end
        @logtype_config['filterConfig'][field]['values'] = Regexp.compile(temp.join('|')) 
      end
    end  
    
    @s247_tz = {'hrs': 0, 'mins': 0} #UTC
    @log_source = Socket.gethostname
    @valid_logtype = true
    @log_upload_allowed = true
    @log_upload_stopped_time = 0
    @s247_datetime_format_string = @logtype_config['dateFormat']
    @s247_datetime_format_string = @s247_datetime_format_string.sub('%f', '%N')
    if !@s247_datetime_format_string.include? 'unix'
      @is_year_present = if @s247_datetime_format_string.include?('%y') || @s247_datetime_format_string.include?('%Y') then true else false end
      if !@is_year_present
	@s247_datetime_format_string = @s247_datetime_format_string+ ' %Y'
      end   
      @is_timezone_present = if @s247_datetime_format_string.include? '%z' then true else false end
      if !@is_timezone_present && @logtype_config.has_key?('timezone')
  @s247_datetime_format_string += '%z'
	tz_value = @logtype_config['timezone']
  if tz_value.start_with?('+')
    @s247_tz['hrs'] = Integer('-' + tz_value[1..2])
    @s247_tz['mins'] = Integer('-' + tz_value[3..4])
  elsif tz_value.start_with?('-')
    @s247_tz['hrs'] = Integer('+' + tz_value[1..2])
    @s247_tz['mins'] = Integer('+' + tz_value[3..4])
  end
      end
    end
    Thread.new { timer_task() }
  end

  def init_http_client(logtype_config)
    require 'net/http/persistent'
    upload_url = 'https://'+logtype_config['uploadDomain']+'/upload'
    @uri = URI(upload_url)
    log.info "Starting HTTP connection to #{upload_url}"
    @s247_http_client = Net::HTTP::Persistent.new name: "fluent-plugin-site24x7", proxy: :ENV
    @s247_http_client.verify_mode = OpenSSL::SSL::VERIFY_NONE
    @s247_http_client.idle_timeout = @http_idle_timeout
    @s247_http_client.read_timeout = @http_read_timeout
    @s247_http_client.override_headers["Content-Type"] = "application/json"
    @s247_http_client.override_headers["Content-Encoding"] = "gzip"
    @s247_http_client.override_headers["X-DeviceKey"] = logtype_config['apiKey']
    @s247_http_client.override_headers["X-LogType"] = logtype_config['logType']
    @s247_http_client.override_headers["X-StreamMode"] = 1
    @s247_http_client.override_headers["User-Agent"] = 'Fluentd'
    if !@s247_http_client.proxy_uri.nil?
        log.info "Using HTTP proxy #{@s247_http_client.proxy_uri.scheme}://#{@s247_http_client.proxy_uri.host}:#{@s247_http_client.proxy_uri.port} username: #{@s247_http_client.proxy_uri.user ? "configured" : "not configured"}, password: #{@s247_http_client.proxy_uri.password ? "configured" : "not configured"}"
    end    
  end

  def get_timestamp(datetime_string)
    begin
        # If the date value is in unix format the no need to process the date string
        if @s247_datetime_format_string.include? 'unix'
            return (if @s247_datetime_format_string == 'unix' then datetime_string+'000' else datetime_string end)
        end
        datetime_string += if !@is_year_present then ' '+String(Time.new.year) else '' end
        if !@is_timezone_present && @logtype_config.has_key?('timezone')
            time_zone = String(@s247_tz['hrs'])+':'+String(@s247_tz['mins'])
            datetime_string += if time_zone.start_with?('-') then time_zone else '+'+time_zone end
        end
        #log.info "datetime_string : (#{datetime_string}), s247_datetime_format_string: (#{@s247_datetime_format_string})"
        datetime_data = DateTime.strptime(datetime_string, @s247_datetime_format_string)
        return Integer(datetime_data.strftime('%Q'))
    rescue Exception => e
      log.error "Exception in parsing date: #{e.message}"
      return 0
    end
  end

  def data_collector()
    if @formatted_line.has_key?('_zl_timestamp')
      applyMasking()
      applyHashing()
      getDerivedFields()
      if !is_filters_matched()
        @formatted_line = {}
        return
      end
      remove_ignored_fields()
      log_size_calculation()
    else
      @formatted_line = {}
      return
    end
  end 

  def get_last_group_inregex(s247_custom_regex)
    return @s247_custom_regex.names[-1]
  end

  def remove_ignored_fields()
    @s247_ignored_fields.each do |field_name|
      if @formatted_line.has_key?field_name
        @formatted_line.delete(field_name)
      end
    end
  end

  def add_message_metadata()
    @log_fields.update({'_zl_timestamp' => get_timestamp(@log_fields[@logtype_config['dateField']]), 's247agentuid' => @log_source})
  end

  def parse_lines(lines)
    parsed_lines = []
    lines.each do |line|
      if !line.empty?
        begin
          @logged = false
          match = line.match(@s247_custom_regex)
          if match
            @formatted_line.update(@old_formatted_line)
            @log_fields = match&.named_captures
            add_message_metadata()
            @old_formatted_line = @log_fields
            @last_line_matched = true
            @trace_started = false             
          elsif @last_line_matched || @trace_started
            is_date_present = !(line.scan(@datetime_regex).empty?)
            @trace_started = !(is_date_present)
            if !(is_date_present) && @old_formatted_line
              if @old_formatted_line.has_key?(@message_key)
                @old_formatted_line[@message_key] += '\n' + line
                @old_log_size += line.bytesize
                @trace_started = true
                @last_line_matched = false
              end
            end
          end
          data_collector()
          if @formatted_line.length >0
            parsed_lines.push(@formatted_line)
          end     
        rescue Exception => e
          log.error "Exception in parse_line #{e.backtrace}"
          @formatted_line = {}
        end
      end
    end
    return parsed_lines
  end

  def is_filters_matched()
    begin
      if @logtype_config.has_key?'filterConfig'
        @logtype_config['filterConfig'].each do |config,value|
          if (@formatted_line.has_key?config)
            if @logtype_config['filterConfig'][config]['values'].match(@formatted_line[config])
              val = true 
            else
              val = false
            end
          end
          if (@logtype_config['filterConfig'][config]['match'] ^ (val))
            return false
          end
        end
      end
    rescue Exception => e
      log.error "Exception occurred in filter: #{e.backtrace}" 
    end
    return true
  end

  def get_json_value(obj, key, datatype=nil)
    if obj != nil && (obj.has_key?key)
      if datatype and datatype == 'json-object'
        arr_json = []
        child_obj = obj[key]
        if child_obj.class == String
          child_obj = Yajl::Parser.parse(child_obj.gsub('\\','\\\\'))
        end             
        child_obj.each do |key, value|
          arr_json.push({'key' => key, 'value' => String(value)})
        end
        return arr_json
      else
        return (if obj.has_key?key then obj[key] else obj[key.downcase] end)
      end
    elsif key.include?'.'
      parent_key = key[0..key.index('.')-1]
      child_key = key[key.index('.')+1..-1]
      child_obj = obj[if obj.has_key?parent_key then parent_key else parent_key.capitalize() end]
      if child_obj.class == String
        child_obj = Yajl::Parser.parse(child_obj.replace('\\','\\\\'))
      end
      return get_json_value(child_obj, child_key,datatype)
    end
  end

  def json_log_applier(line)
    json_log_size=0
    @formatted_line = {}
    @log_fields = {}
    event_obj = if line.is_a?(String) then Yajl::Parser.parse(line) else line end
    @logtype_config['jsonPath'].each do |path_obj|
      value = get_json_value(event_obj, path_obj[if path_obj.has_key?'key' then 'key' else 'name' end], path_obj['type'])
      if value
        @log_fields[path_obj['name']] = value 
        json_log_size+= String(value).bytesize - (if value.class == Array then value.size*20 else 0 end)
      end
    end
    for key,regex in @sub_pattern do
      if @log_fields.has_key?(key)
        matcher = regex.match(@log_fields.delete(key))
        if matcher
          @log_fields.update(matcher.named_captures)
          @formatted_line.update(@log_fields)
        end 
      end
    end
    add_message_metadata()
    @formatted_line.update(@log_fields)
    data_collector()
    if @formatted_line.length >0
      return true
    else
      return false
    end 
  end

  def json_log_parser(lines)
    parsed_lines = []
    lines.each do |line|
      begin
        @logged = false
        if !line.empty?
          if line[0] == '{' && @json_data[-1] == '}'
            if json_log_applier(@json_data)
              parsed_lines.push(@formatted_line)
            end
            @json_data=''
          end
          @json_data += line
        end
      rescue Exception => e
        log.error "Exception in parse_line #{e.backtrace}"
      end
    end
    return parsed_lines
  end

  def ml_regex_applier(ml_trace, ml_data)
    begin
      matcher = @s247_custom_regex.match(@ml_trace)  
      @log_fields = matcher.named_captures
      @log_fields.update(@ml_data)
      add_message_metadata()
      @formatted_line.update(@log_fields)
    rescue Exception => e
      log.error "Exception occurred in ml_parser : #{e.backtrace}"
    end
  end
  
  def ml_log_parser(lines)
    parsed_lines = []
    lines.each do |line|
      if !line.empty?
        begin
          @logged = false
          ml_start_matcher = @ml_regex.match(line)
          if ml_start_matcher || @ml_end_line_found
            @ml_found = ml_start_matcher
            @ml_end_line_found = false
            @formatted_line = {}
            if @ml_trace.length > 0 
              begin
                  ml_regex_applier(@ml_trace, @ml_data)
                  if @ml_trace_buffer && @formatted_line
                      @formatted_line[@message_key] = @formatted_line[@message_key] + @ml_trace_buffer
                  end
                  data_collector()
                  if @formatted_line.length >0
                    parsed_lines.push(@formatted_line)
                  end    
                  @ml_trace = ''
                  @ml_trace_buffer = ''
                  if @ml_found
                    @ml_data = ml_start_matcher.named_captures
                  else
                      @ml_data = {}
                  end
                  @ml_count = 0
              rescue Exception => e
                log.error "Exception occurred in ml_parser : #{e.backtrace}"
                end
            elsif @ml_found
              @ml_data = ml_start_matcher.named_captures
            end
          elsif @ml_found
            if @ml_count < @max_ml_count
              @ml_trace += '<NewLine>' + line
            elsif @ml_end_regex && @ml_end_regex.match(line)
              @ml_end_line_found = True
            elsif (@ml_count - @max_ml_count) < @max_trace_line
              @ml_trace_buffer += "\n" + line
            end
            @ml_count += 1
          end
        rescue Exception => e
          log.error "Exception occurred in ml_parser : #{e.backtrace}"
        end
      end
    end
    return parsed_lines
  end

  def format(tag, time, record)
    if @valid_logtype && (@log_upload_allowed || (time.to_i - @log_upload_stopped_time > S247_LOG_UPLOAD_CHECK_INTERVAL))
      if (record.size == 1)
        if record.has_key?'message'
          [record['message']].to_msgpack
        end
      else
        [record.to_json].to_msgpack
      end
    end
  end     

  def write(chunk)
    current_chunk_id = "#{chunk.dump_unique_id_hex(chunk.unique_id)}"
    begin
      events = Array.new
      chunk.msgpack_each do |record|
        next if record.empty?
        events.push record[0]
      end
      process_http_events(events, current_chunk_id)
    rescue Exception => e
      log.error "Exception #{e.backtrace}"
    end
  end

  def process_http_events(events, current_chunk_id)
    @before_time = Time.now
    batches = batch_http_events(events)
    batches.each do |batched_event|
      formatted_events, @log_size = format_http_event_batch(batched_event)
      if (formatted_events.length>0)
        formatted_events = gzip_compress(formatted_events)
        send_logs_to_s247(formatted_events, @log_size, current_chunk_id)
      end
    end 
  end

  def batch_http_events(encoded_events)
    batches = []
    current_batch = []
    current_batch_size = 0
    encoded_events.each_with_index do |encoded_event, i|
      current_event_size = String(encoded_event).bytesize
      if current_event_size > S247_MAX_RECORD_SIZE
        encoded_event = encoded_event[0..(S247_MAX_RECORD_SIZE-DD_TRUNCATION_SUFFIX.length)]+DD_TRUNCATION_SUFFIX
        current_event_size = encoded_event.bytesize
      end

      if (i > 0 and i % S247_MAX_RECORD_COUNT == 0) or (current_batch_size + current_event_size > S247_MAX_BATCH_SIZE)
        batches << current_batch
        current_batch = []
        current_batch_size = 0
      end

      current_batch_size += current_event_size
      current_batch << encoded_event
    end
    batches << current_batch
    batches
  end

  def format_http_event_batch(events)
    parsed_lines = []
    @log_size = 0
    @old_log_size=0
    if @logtype_config.has_key?'jsonPath'
      parsed_lines = json_log_parser(events)
    elsif @logtype_config.has_key?'ml_regex'
      parsed_lines = ml_log_parser(events)
    else
      parsed_lines = parse_lines(events)
    end
    if (parsed_lines.length > 0)
      return Yajl.dump(parsed_lines), @log_size
    end
    return [],0
  end

  def gzip_compress(payload)
    gz = StringIO.new
    gz.set_encoding("BINARY")
    z = Zlib::GzipWriter.new(gz, 9)
    begin
      z.write(payload)
    ensure
      z.close
    end
    gz.string
  end

  def send_logs_to_s247(gzipped_parsed_lines, log_size, current_chunk_id)
      request = Net::HTTP::Post.new @uri.request_uri
      request.body = gzipped_parsed_lines

      sleep_interval = @retry_interval
     begin
        retries = 0
        first_upload_time =  Time.now
        while true
          need_retry = false
          begin
            @s247_http_client.override_headers["Log-Size"] = @log_size
            @s247_http_client.override_headers["upload-id"] = current_chunk_id
            response = @s247_http_client.request @uri, request
            resp_headers = response.each_header.to_h
            
            if response.code == '200'
              if resp_headers['x-uploadid'] == nil
                log.error "[#{current_chunk_id}]:upload id is empty hence retry flag enabled #{resp_headers}"
                need_retry = true
              else
		            @log_upload_allowed = true
                log.debug "[#{current_chunk_id}]:Successfully sent logs with size #{gzipped_parsed_lines.size} / #{@log_size} to site24x7. Upload Id : #{resp_headers['x-uploadid']}"
              end
            elsif response.code == '400'
              if resp_headers.has_key?'log_license_exceeds' and resp_headers['log_license_exceeds'] == 'True'
                log.error "[#{current_chunk_id}]:Log license limit exceeds so not able to send logs"
                @log_upload_allowed = false
		            @log_upload_stopped_time =Time.now.to_i
              elsif resp_headers.has_key?'blocked_logtype' and resp_headers['blocked_logtype'] == 'True'
                log.error "[#{current_chunk_id}]:Max upload limit reached for log type"
                @log_upload_allowed = false
		            @log_upload_stopped_time =Time.now.to_i
              elsif resp_headers.has_key?'api_upload_enabled' and resp_headers['api_upload_enabled'] == 'False'
                log.error "[#{current_chunk_id}]:API upload not enabled for log type : "
                @log_upload_allowed = false
		            @log_upload_stopped_time =Time.now.to_i
              elsif resp_headers.has_key?'invalid_logtype' and resp_headers['invalid_logtype'] == 'True'
                log.error "[#{current_chunk_id}]:Log type not present in this account so stopping log collection"
		            @valid_logtype = false
              elsif resp_headers.has_key?'invalid_account' and resp_headers['invalid_account'] == 'True'
                log.error "[#{current_chunk_id}]: Invalid account so stopping log collection"
		            @valid_logtype = false
              else
                log.error "[#{current_chunk_id}]: Upload failed for reason : #{response.message}"
              end
            else
              log.error "[#{current_chunk_id}]:Response Code #{response.code} from Site24x7, so retrying (#{retries + 1}/#{@max_retry})"
              need_retry = true
            end
          rescue StandardError => e
            log.error "[#{current_chunk_id}]:Error connecting to Site24x7. exception: #{e} (#{retries + 1}/#{@max_retry})"
            need_retry = true
          end

          if need_retry
            retries += 1 
            if (retries >= @max_retry && @max_retry > 0) || (Time.now > first_upload_time + @retry_timeout && @retry_timeout > 0)
              log.error "[#{current_chunk_id}]: Internal max retries(#{max_retry}) or retry_timeout : #{first_upload_time + @retry_timeout} reached"
              break
            end
            log.info "[#{current_chunk_id}]:Going to retry the upload at #{Time.now + sleep_interval}"
            sleep(sleep_interval)
            sleep_interval *= 2
            if sleep_interval > @maxretry_interval
                sleep_interval = @maxretry_interval
            end
          else
            return
          end
        end
      rescue Exception => e
        log.error "Exception occurred in sendig logs : #{e.backtrace}"
      end
  end

  def log_the_holded_line()
    @log_size = 0
    if @logged == false
      if (@ml_trace.length>0)
        ml_regex_applier(@ml_trace, @ml_data)
        if @ml_trace_buffer
          if !(@formatted_line.empty?)
            @formatted_line[@message_key] = @formatted_line[@message_key] + @ml_trace_buffer 
          else
            @ml_trace += @ml_trace_buffer.gsub('\n', '<NewLine>')
            ml_regex_applier(@ml_trace, @ml_data)
          end
          @ml_trace_buffer = ''          
        end    
        @ml_trace = ''
      elsif (@json_data.length>0)
        if !(json_log_applier(@json_data))
          @formatted_line={}
        end
        @json_data = ''
      elsif @old_formatted_line
        @formatted_line.update(@old_formatted_line)
        data_collector()
        @old_formatted_line = {}
      end
      @logged = true
      if @format_record
        @custom_parser.format_record()
      end
      if !(@formatted_line.empty?)
        return @formatted_line
      end
    end
    return nil
  end

  def applyMasking()
    if @masking_config
      begin
        for key,value in @masking_config do
          adjust_length = 0
          mask_regex = @masking_config[key]["regex"]
          if @formatted_line.has_key?key
            field_value = @formatted_line[key]
            if !(mask_regex.eql?(@general_regex))
              matcher = field_value.to_enum(:scan, mask_regex).map { Regexp.last_match }
              if matcher
                (0..(matcher.length)-1).map do |index| 
                  start = matcher[index].offset(1)[0]  
                  _end = matcher[index].offset(1)[1]
                  if ((start >= 0) && (_end > 0))
                    start = start - adjust_length
                    _end = _end - adjust_length
                    adjust_length += (_end - start) - @masking_config[key]['string'].bytesize
                    field_value = field_value[0..(start-1)] + @masking_config[key]['string'] + field_value[_end..field_value.bytesize]
                  end
                end
              end
              @formatted_line[key] = field_value
            else
              @formatted_line[key] = @masking_config[key]['string']
            end
          end
        end
      rescue Exception => e
        log.error "Exception occurred in masking : #{e.backtrace}"
      end        
    end
  end
  
  def applyHashing()
    if @hashing_config
      begin
        for key,value in @hashing_config do
          hash_regex = @hashing_config[key]["regex"]
          if @formatted_line.has_key?key 
            field_value = @formatted_line[key]
            if (hash_regex.eql?(@general_regex))
              hash_string =  Digest::SHA256.hexdigest(field_value)
              field_value = hash_string
            else 
              adjust_length = 0 
              matcher = field_value.to_enum(:scan, hash_regex).map { Regexp.last_match }
              if matcher
                (0..(matcher.length)-1).map do |index| 
                  start = matcher[index].offset(1)[0] 
                  _end = matcher[index].offset(1)[1] 
                  if ((start >= 0) && (_end > 0))
                    start = start - adjust_length
                    _end = _end - adjust_length
                    hash_string =  Digest::SHA256.hexdigest(field_value[start..(_end-1)])
                    adjust_length += (_end - start) - hash_string.bytesize
                    field_value = field_value[0..(start-1)] + hash_string + field_value[_end..field_value.bytesize]
                  end
                end
              end
            end
            @formatted_line[key] = field_value
          end
        end
      rescue Exception => e
        log.error "Exception occurred in hashing : #{e.backtrace}"
      end
    end
  end
  
  def getDerivedFields()
    if @derived_config
      begin
        for key,value in @derived_fields do
          for each in @derived_fields[key] do
              if @formatted_line.has_key?key
                match_derived = each.match(@formatted_line[key])
                if match_derived
                  @formatted_line.update(match_derived.named_captures) 
                end
                break
              end
          end
        end
      rescue Exception => e
        log.error "Exception occurred in derived fields : #{e.backtrace}"
      end
    end
  end
  
  def log_size_calculation()
    data_exclusion = ["_zl", "s247", "inode"]
    @formatted_line.each do |field, value|
      unless data_exclusion.any? { |exclusion| field.start_with?(exclusion) }
        @log_size += value.to_s.bytesize
      end
    end
  end

  def timer_task()
    while true
      @after_time = Time.now
      if @before_time
        diff = @after_time-@before_time
        if diff.to_i > 29
          out = log_the_holded_line()
          if out != nil
            out = Yajl.dump([out])
            out = gzip_compress(out)
            send_logs_to_s247(out, @log_size, 'holded_line')
          end
        end
      end
      sleep(30)
    end
  end

end
