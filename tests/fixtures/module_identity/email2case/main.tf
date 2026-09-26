module "classifier" {
  source        = "../modules/consumer_sqs"
  function_name = "email2case-classifier"
  queue_arn     = "arn:aws:sqs:eu-west-1:123456789012:classifier"
}

module "data_fusion" {
  source        = "../modules/consumer_sns"
  function_name = "email2case-data-fusion"
  topic_arn     = "arn:aws:sns:eu-west-1:123456789012:data-fusion"
}

module "kafka_lambda_consumer" {
  source        = "../modules/consumer_kafka"
  function_name = "email2case-kafka-consumer"
  cluster_arn   = "arn:aws:kafka:eu-west-1:123456789012:cluster/email2case/abc"
}

module "kafka_producer" {
  source        = "../modules/consumer_sqs"
  function_name = "email2case-kafka-producer"
  queue_arn     = "arn:aws:sqs:eu-west-1:123456789012:producer"
}
