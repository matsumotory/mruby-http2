#include "mrb_http2.h"
#include "mrb_http2_server.h"

static mrb_value mrb_http2_req_filename(mrb_state *mrb, mrb_value self)
{
  mrb_http2_data_t *data = DATA_PTR(self);
  mrb_http2_request_rec *r = data->r;

  return mrb_str_new_cstr(mrb, r->filename);
}

void mrb_http2_request_class_init(mrb_state *mrb, struct RClass *http2)
{
  struct RClass *req;

  req = mrb_define_class_under(mrb, http2, "Request", mrb->object_class);

  //mrb_define_method(mrb, req, "initialize", mrb_http2_req_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, req, "filename", mrb_http2_req_filename, MRB_ARGS_NONE());
  //mrb_define_method(mrb, req, "filename=", mrb_http2_req_get_filename, MRB_ARGS_REQ(1));

  DONE;
}

