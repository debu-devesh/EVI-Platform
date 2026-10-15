output "alb_dns_name" {
  description = "Public URL to access EVI"
  value       = aws_lb.main.dns_name

}

output "ecr_repository_url" {
  description = "ECR repo-push your Docker image here"
  value       = aws_ecr_repository.app.repository_url

}
output "efs_id" {
  description = "EFS file system ID"
  value       = aws_efs_file_system.persist.id

}