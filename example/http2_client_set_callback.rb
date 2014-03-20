r = HTTP2::Client.get 'https://127.0.0.1:8080/index.html'

p r.response
p r.body
p r.request_headers
p r.response_headers
p r.status
p r.body
p r.body_length
p r.stream_id

p "---- set callback version ----"

s = HTTP2::Client.new
s.uri = 'https://127.0.0.1:8080/index.html'
s.on_header_callback {
    p "header callback"
}
s.send_callback {
    p "send_callback"
}
s.recv_callback {
    p "recv_callback"
}
s.before_frame_send_callback {
    p "before_frame_send_callback"
}
s.on_frame_send_callback {
    p "on_frame_send_callback"
}
s.on_frame_recv_callback {
    p "on_frame_recv_callback"
}
s.on_stream_close_callback {
    p "on_stream_close_callback"
}
s.on_data_chunk_recv_callback {
    p "on_data_chunk_recv_callback"
}
r = s.get
p r.response

