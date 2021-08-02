# Fluentd output plugin for Site24x7

This output plugin allows parse and sending logs directly from Fluentd to Site2x7 - so you don't have to use a separate log shipper.


## Installation

To add the plugin to your fluentd agent, use the following command:

```
$ gem install fluent-plugin-site24x7
```
If you installed the td-agent instead

```
$ /usr/sbin/td-agent-gem install fluent-plugin-site24x7
```

## Usage

**Configure the output plugin**

To match events and send them to Site24x7, simply add the following code to your configuration file.

```cfg
# Match events tagged with "site24x7.**" and send them to Site24x7
<match site24x7.**>

  @type site24x7
  @id site24x7_agent
  log_type_config <your_log_type_config>

  # Optional parameters
  max_retry '3'
  retry_interval '2'
  http_idle_timeout '5'
  http_read_timeout '30'
  
  # Optional http proxy
  http_proxy 'http://user:passs@mproxy.host:proxy.port'

  <buffer>
          @type memory
          flush_thread_count 4
          flush_interval 3s
          chunk_limit_size 5m
          chunk_limit_records 500
  </buffer>

</match>
```
After a restart of FluentD, any events tagged with site24x7 are shipped to site24x7 platform.

## Parameters
As fluent-plugin-site24x7 is an output_buffer, you can set all output_buffer properties like it's describe in the [fluentd documentation](http://docs.fluentd.org/articles/output-plugin-overview#buffered-output-parameters).

Property | Description | Default Value
------------ | -------------|------------
log_type_config | log_type_config for your configured log type in site24x7 | nil
max_retry | How many times to resend failed uploads | 3
retry_interval |  How long to sleep initially between retries, exponential step-off | 2 seconds
http_idle_timeout | Timeout in seconds that the http persistent connection will stay open without traffic | 5 seconds
http_read_timeout | Timeout in seconds when the socket connects until the connection breaks | 30 secods
http_proxy | Your proxy uri | nil

## Release Notes

* 0.1.0 - Initial Release
