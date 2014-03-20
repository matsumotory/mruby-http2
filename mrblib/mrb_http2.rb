module HTTP2
  class Client
    def Client.get(url)
      response_hash = http2_get(url)
      Response.new(response_hash)
    end
    def get
      response_hash = inst_get
      Response.new(response_hash)
    end
  end
  class Response
    def initialize(response_hash)
      @response = response_hash
    end
    def response; @response; end
    def request_headers; @response[:request_headers]; end
    def response_headers; @response[:response_headers]; end
    def status; @response[:response_headers][":status"].to_i; end
    def body; @response[:body]; end
    def body_length; @response[:body_length]; end
    def stream_id; @response[:stream_id]; end
  end
end
