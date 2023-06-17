variable "vpc_id" {
  type = string
}

variable "subnet_cidr_blocks" {
  type = list(string)
}

variable "subnet_ids" {
  type = list(string)
}

variable "sync_efs_subnet_arn" {
  type = string
}

variable "dns_zone" {
  type = string
}

variable "server_name" {
  type = string
}

variable "cpu" {
  type    = number
  default = 1024
}
variable "memory" {
  type    = number
  default = 4096
}

variable "startup_min" {
  type    = number
  default = 10
}
variable "shutdown_min" {
  type    = number
  default = 20
}

variable "gamemode" {
  type    = string
  default = "survival"

}

variable "difficulty" {
  type    = string
  default = "normal"
}