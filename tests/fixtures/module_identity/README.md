Real-world module layout used by tests/test_module_instance_identity.py.

- `email2case/` (root) calls four module instances: `classifier` and
  `kafka_producer` share `modules/consumer_sqs`; `data_fusion` uses
  `modules/consumer_sns`; `kafka_lambda_consumer` uses `modules/consumer_kafka`.
  Every reusable module names its Lambda `aws_lambda_function.this`.
- `platform/` (root) calls `modules/sentry` and `modules/observability`, which
  both name their load balancer `aws_lb.nlb` (`load_balancer_type = "network"`).

Before module-instance identity, the HCL scan flattened all of this to one
`aws_lambda_function.this` and one `aws_lb.nlb`.
