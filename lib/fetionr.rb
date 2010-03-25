#===============================================================================
# = Author
# shaobin0604@qq.com
#
# = License
# MIT License
#
# = Dependency
# gem install uuid
#
# = Acknowledgment
# thanks to cocobear's pyfetion lib
# [http://cocobear.info/blog/2008/12/03/write-fetion-with-python-pyfetion/] 
# and nathan's ananysis of fetion protocol
# [http://hi.baidu.com/nathan2007]
#
# == usage
# Usage: ruby fetionr.rb [options]
#
# Example:
#
# ruby fetionr.rb -m mobile_no -p password -c sms_content
# ruby fetionr.rb -m mobile_no -p password -r receiver_mobile_no -c sms_content
#
#    -m, --mobile MOBILE              Fetion mobile number
#    -p, --password PASSWORD          Fetion password
#    -c, --content CONTENT            Fetion message content
#    -r, --receivers MOBILE           Receivers' Fetion mobile numbers, if no
#                                     recievers, send sms to yourself
#
# different mode:
#        --debug                      debug mode
#        --silence                    silence mode
#
# Common options:
#    -h, --help                       Show this message
#===============================================================================

require 'rubygems'
require 'socket'
require 'digest/md5'
require 'uuid'
require 'binascii'
require 'net/http'
require 'net/https'
require 'cgi'
require 'logger'
require 'openssl'
require 'open-uri'
require 'optparse'

class Fetionr
  class SIPC
    attr_accessor :command, :header, :body
    
    def initialize(command = '', header = [], body = '')
      @command = command
      @header = header
      @body = body
    end

    def to_s
      @header << ['L', @body.length.to_s]
      header_str = @header.inject('') do |str, pair|
        str << "%s: %s\r\n" % [pair[0], pair[1]]
      end

      @command + "\r\n" + header_str + "\r\n" + @body
    end
  end
  
  FETION_VERSION = "2008"
  FETION_SIPC_VERSION = "SIP-C/2.0"
  #"SIPP" USED IN HTTP CONNECTION
  FETION_SIPP= "SIPP"
  FETION_NAV_URL = "nav.fetion.com.cn"
  FETION_CON_TYPE = ["TCP", "HTTP"]
  FETION_CONFIG_URL  = "http://nav.fetion.com.cn/nav/getsystemconfig.aspx"
  
  REG_PACKET_BODY    = '<args><device type="PC" version="295628128" client-version="3.4.1280" /><caps value="simple-im;im-session;temp-group;personal-group" /><events value="contact;permission;system-message;personal-group;compact" /><oem-tag value="cmcc.sjb0.inet.0024" /><user-info attributes="all" /><presence><basic value="%s" desc="" /></presence></args>'
  CONFIG_PACKET_BODY = '<config><user mobile-no="%s" /><client type="PC" version="3.2.0540" platform="W5.1" /><servers version="0" /><service-no version="0" /><parameters version="0" /><hints version="0" /><http-applications version="0" /><client-config version="0" /></config>'

  def initialize(level=Logger::DEBUG, log_dev=STDOUT)
    # log config
    @log = Logger.new(log_dev)
    @log.level = level

    #   login info
    @login = false
    @mobile_no = ''
    @passwd = ''
    @con_type = 'TCP'
    @see = false
    
    #   system config info
    @system_config = ''
    @sipc_proxy = ''
    @sipc_ssi_portal = ''
    @http_tunnel = ''

    #   auth info
    @ssic = ''

    @call_id = 1
    @command_seq = 1
  end


  #
  # Login fetion im
  #
  # @param[String]  mobile_no - mobile phone number
  # @param[String]  passwd -
  # @param[String]  con_type - connection type, should be one of 'TCP', 'HTTP'
  # @param[Boolean] see - wheather let my friend see I am on line
  # @param[Boolean] https_auth - wheather use https to connect ssi portal
  #
  def login(mobile_no, passwd, con_type = 'TCP', see = false, https_auth = true)
    @mobile_no = mobile_no
    @passwd = passwd
    raise ArgumentError, 'con_type must be in ["TCP", "HTTP"]' unless FETION_CON_TYPE.include?(con_type)
    @con_type = con_type
    @see = see
    @https_auth = https_auth

    # step 1 get_system_config
    get_system_config

    # step 2 sign in ssi portal
    login_ssi_portal

    # step 3 sign in sipc proxy
    login_sipc_proxy
  end

  #
  # send sms
  #
  # @param[String] to_uri - the receiver's uri, if nil then send to yourself
  # @param[String] msg - message to send
  # @return[code, status]
  #
  def send_sms(msg, to = nil)
    if to.nil? # if not provide to param, send to yourself
      to = @uri
    elsif mobile_no?(to)
      to = "tel:" + to
    end
    
    packet = build_sms_packet(@sid, @domain, to, msg)
    resp = send_sip_packet(packet)
    code, status = get_response_status(resp)
    @log.info {"code -> #{code}\nstatus -> #{status}"}
    return code, status
  end

  def logout()
    
  end

  private

  #
  # create tcp socket to connect to sipc proxy server
  #
  def init_socket
    host, port = @sipc_proxy.split(':')
    begin
      @socket = TCPSocket.new(host, port)
    rescue Exception => e
      @log.error {"Cannot connect to sipc proxy -> #{e}"}
      raise Exception, "Cannot connect to sipc proxy -> #{e}"
    end
  end

  #
  # @param[String] packet - the sipc request packet string
  # @return[String] - the sipc response packet string
  #
  def send_sip_packet(packet)
    init_socket if @socket.nil?
    begin
      packet_str = packet.to_s
      @log.debug {"send packet -> \n#{packet_str}"}
      count = @socket.write(packet_str)
      @socket.flush
      @log.debug {"send #{count} bytes."}
      resp = recv_sip_packet
      @log.debug {"resp is #{resp}"}
      resp
    rescue Exception => e
      @log.error {"send sip packet error => #{e}"}
      @socket.close
      @socket = nil
    end
  end

  #
  # @return[String] - the sipc response packet string
  #
  def recv_sip_packet
    raise Exception, "socket closed" if @socket.nil?
    total_buf = ""
    buf_size = 1024
    buf = ""
    body_len = 0
    header_len = 0
    total_len = 0
    left = 0

    find_sep = false
    begin
      loop do
        @socket.readpartial(buf_size, buf)
        total_buf << buf
        #@log.debug {"recv buf -> #{buf}"}

        if !find_sep && buf.include?("\r\n\r\n") # find header, body separator
          find_sep = true
          if buf =~ /L: (\d+)/ #find length header, has body
            body_len = $~[1].to_i
            header_len = $~.end(1) + 4
            total_len = header_len + body_len
            @log.debug {"total_len -> #{total_len}\nbody_len -> #{body_len}\nheader_len -> #{header_len}"}
          else # no body
            return total_buf
          end
        end
        
        if find_sep
          left = total_len - total_buf.length
          return total_buf if left <= 0
        end
      end
    rescue EOFError => e
      @log.error {"recv sip packet error => #{e}"}
      @socket.close
      @socket = nil
    end
  end

  #
  # get response status
  #
  # @param[String] resp - the sipc response string
  # @return[status_code, status_string]
  def get_response_status(resp)
    if resp =~ /#{FETION_SIPC_VERSION} (\d{3}) (.*)\r\n/
      code = $~[1].to_i
      str = $~[2]
      return code, str
    else
      return -1, 'error'
    end
  end

  def get_system_config
    body = CONFIG_PACKET_BODY % @mobile_no
    #@log.debug {"body -> %s" % body}
    header = {'User-Agent' => 'IIC2.0/PC 3.2.0540', 'Content-Type' => 'text/xml'}

    resp = http_post(FETION_CONFIG_URL, body, header)

    #@log.debug {"resp -> %s" % resp.content}
    case resp
    when Net::HTTPSuccess
      @system_config = resp.body
      parse_system_config
    else
      raise Exception, "get_system_config fail -> #{resp.inspect}"
    end
  end

  def parse_system_config
    @sipc_ssi_portal = @system_config[%r{<ssi-app-sign-in>(.*)</ssi-app-sign-in>}, 1]
    @sipc_proxy = @system_config[%r{<sipc-proxy>(.*)</sipc-proxy>}, 1]
    @http_tunnel = @system_config[%r{<http-tunnel>(.*)</http-tunnel>}, 1]

    @log.debug {"sipc_ssi_protal -> %s\nsipc_proxy -> %s\nhttp_tunnel -> %s" % [@sipc_ssi_portal, @sipc_proxy, @http_tunnel]}
  end

  def login_ssi_portal
    if @https_auth
      url = "#{@sipc_ssi_portal.sub(/https:\/\/\d+\.\d+\.\d+\.\d+\//, "https://uid.fetion.com.cn/")}?mobileno=#{@mobile_no}&pwd=#{CGI::escape(@passwd)}"
      #   url = "#{@sipc_ssi_portal}?mobileno=#{@mobile_no}&pwd=#{CGI::escape(@passwd)}"
    else
      # http works also, damn it
      url = "#{@sipc_ssi_portal.sub("https", "http")}?mobileno=#{@mobile_no}&pwd=#{CGI::escape(@passwd)}"
    end
    @log.debug {"ssi login url -> #{url}"}

    begin
      resp = https_get(url)
      case resp
      when Net::HTTPSuccess
        @log.debug {"login ssi portal resp header -> #{resp['Set-Cookie']}"}
        @ssic = resp['Set-Cookie'][/ssic=(.*);/, 1]
        @sid = resp.body[/sip:(.*)@/, 1]
        @uri = resp.body[/uri="(.*)" mobile-no/, 1]
        @status = resp.body[/user-status="(\d+)"/, 1]
        @domain = resp.body[/@(.*);/, 1]
        
        @log.debug {"ssic -> %s\nsid -> %s\nuri -> %s\nstatus -> %s\ndomain -> %s" % [@ssic, @sid, @uri, @status, @domain]}
      else
        raise Exception, "login ssi portal fail -> #{resp.inspect}"
      end
    rescue Exception => e
      raise Exception, "login ssi portal fail -> #{e} at -> #{$@}"
    end
  end

  def login_sipc_proxy
    packet1 = build_reg_1_packet(@sid, @domain, @see)
    resp1 = send_sip_packet(packet1.to_s)
    

    packet2 = build_reg_2_packet(@sid, @domain, @see, resp1)
    resp2 = send_sip_packet(packet2.to_s)
    
    if resp2.include? "#{FETION_SIPC_VERSION} 200 OK"
      @log.info {"login ok"}
      @login = true
    else
      @log.error {"login fail"}
      raise Exception, "login fail"
    end
  end
  
  

  def http_post(url, body, header={})
    uri = URI.parse(url)
    Net::HTTP.start(uri.host, uri.port) do |http|
      http.post(uri.path, body, header)
    end
  end

  def http_get(url, header = {})
    uri = URI.parse(url)
    Net::HTTP.start(uri.host, uri.port) do |http|
      http.get(uri.path + '?' + uri.query, header)
    end
  end

  def https_get(url, header = {})
    uri = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE

    http.start do |c|
      http.get(uri.path + '?' + uri.query, header)
    end
  end

  # use httpcient to overload
  #  def http_post(url, body, header={})
  #    clnt = HTTPClient.new
  #    clnt.post(url, body, header)
  #  end
  #
  #  def http_get(url, query=nil, header = {})
  #    clnt = HTTPClient.new
  #    clnt.get(url, query, header)
  #  end
  #
  #  def http_get_content(url, query=nil, header = {})
  #    clnt = HTTPClient.new
  #    clnt.get_content(url, query, header)
  #  end

  def get_cnonce
    Digest::MD5.hexdigest(UUID.new.generate).upcase
  end

  def get_response_sha1(nonce, cnonce, sid, domain)
    hash_passwd = hash_passwd()
    hash_passwd_str = Binascii::hex2bin(hash_passwd[8..-1])
    key = Digest::SHA1.digest("%s:%s:%s" % [sid, domain, hash_passwd_str])
    h1  = Digest::MD5.hexdigest("%s:%s:%s" % [key,nonce,cnonce]).upcase
    h2  = Digest::MD5.hexdigest("REGISTER:%s" % sid).upcase
    response = Digest::MD5.hexdigest("%s:%s:%s" % [h1,nonce,h2]).upcase
  end

  def hash_passwd
    salt = "wzm\x03"
    src = salt + Digest::SHA1.digest('xiaoyvvkbsse0604')
    result = "777A6D03" + Digest::SHA1.hexdigest(src).upcase
  end

  def get_salt
    hash_passwd[0, 8]
  end

  def build_reg_1_packet(sid, domain, see)
    # build reg step 1 packet
    command, header = ini_msg_part('R', domain, sid)
    
    body = see ? REG_PACKET_BODY % '400': REG_PACKET_BODY % '0'

    SIPC.new(command, header, body)
  end

  def build_reg_2_packet(sid, domain, see, resp)
    # got nonce
    nonce = resp[/nonce="(.*)"/, 1]

    # build cnonce
    cnonce = get_cnonce

    # build response
    response = get_response_sha1(nonce, cnonce, sid, domain)

    # get salt
    salt = get_salt

    # build reg step 2 packet
    command, header = ini_msg_part('R', domain, sid, 1, 2)
    
    header << ['A', 'Digest algorithm="SHA1-sess",response="%s",cnonce="%s",salt="%s"' % [response,cnonce,salt]]
    
    body = see ? REG_PACKET_BODY % '400': REG_PACKET_BODY % '0'

    SIPC.new(command, header, body)
  end

  def build_sms_packet(sid, domain, to_uri, msg)
    command, header = ini_msg_part('M', domain, sid, 1, 1)

    header << ['T', to_uri]
    header << ['N', 'SendSMS']

    body = msg

    SIPC.new(command, header, body)
  end

  #
  # @param[String] type -  the request type
  # @param[String] domain - the domain
  def ini_msg_part(type, domain, sid, call_id = 1, command_seq = 1)
    command = '%s %s %s' % [type, domain, FETION_SIPC_VERSION]
    header = [
      ['F', sid],
      ['I', call_id],
      ['Q', "%s %s" % [command_seq, type]],
    ]
    return command, header
  end

  #
  # @param[String] str - mobile phone number
  # @return[Boolean]
  def mobile_no?(str)
    str.length == 11 && 
      isdigit?(str) &&
      %w{134 135 136 137 138 139 150 151 157 158 159 187 188}.include?(str[0, 3]) ?
      true: false
  end

  def isdigit?(str)
    str.to_i.to_s == str
  end
end


if __FILE__ == $0
  options = {}

  OptionParser.new do |opts|
    # Set a banner, displayed at the top of the help screen.
    opts.banner = "Usage: ruby fetionr.rb [options]"

    opts.separator ""
    opts.separator <<-EOF
Example: 
ruby fetionr.rb -m mobile_no -p password -c sms_content
ruby fetionr.rb -m mobile_no -p password -r receiver_mobile_no -c sms_content
EOF

    opts.on('-m', '--mobile MOBILE', 'Fetion mobile number') do |mobile|
      options[:mobile_no] = mobile
    end

    opts.on('-p', '--password PASSWORD', 'Fetion password') do |password|
      options[:password] = password
    end

    opts.on('-c', '--content CONTENT', 'Fetion message content') do |content|
      options[:content] = content
    end

    opts.on('-r', '--receivers MOBILE', Array, "Receivers' Fetion mobile numbers, if no recievers, send sms to yourself") do |receivers|
      options[:receivers] = receivers
    end

    opts.separator ""
    opts.separator "different mode:"

    opts.on('--debug', 'debug mode') do
      options[:logger_level] = Logger::DEBUG
    end

    opts.on('--silence', 'silence mode') do
      options[:logger_level] = Logger::ERROR
    end

    opts.separator ""
    opts.separator "Common options:"

    opts.on_tail("-h", "--help", "Show this message") do
      puts opts
      exit
    end

    opts.parse!
  end

  begin
    raise Exception.new('You must input your mobile number, password and content') unless options[:mobile_no] and options[:password] and options[:content]

    f = options[:logger_level] ? Fetionr.new(options[:logger_level]) : Fetionr.new
    
    f.login(options[:mobile_no], options[:password])

    if options[:receivers]
      f.send_sms(options[:content], options[:receivers])
    else
      f.send_sms(options[:content], options[:mobile_no])
    end

    f.logout

  rescue Exception => e
    puts e.message
    puts "Please use 'ruby fetionr.rb -h' to get more details"
  end
end
