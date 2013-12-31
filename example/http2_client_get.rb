r = HTTP2::Client.get "https://106.186.112.116/"
p r.request_headers
p r.response_headers
if r.status == 200
  p "------ body ------"
  #p r.body
else
  p "error: #{r.status}"
end

