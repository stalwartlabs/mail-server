variable "TARGET" {
  default = "$TARGET"
}
variable "GHCR_REPO" {
  default = "$GHCR_REPO"
}
variable "BUILD_ENV" {
  default = "$BUILD_ENV"
}
variable "SUFFIX" {
  default = "$SUFFIX"
}
variable "DOCKER_PLATFORM" {
  default = "$DOCKER_PLATFORM"
}
target "docker-metadata-action" {}
target "build" {
  secret = [
    "type=env,id=ACTIONS_RESULTS_URL",
    "type=env,id=ACTIONS_RUNTIME_TOKEN"
  ]
  args = {
    TARGET = "${TARGET}"
    BUILD_ENV = equal("", "${BUILD_ENV}") ? null : "${BUILD_ENV}"
  }
  target = "binaries"
  cache-from = [
    "type=registry,ref=${GHCR_REPO}-buildcache:${TARGET}"
  ]
  cache-to = [
    "type=registry,ref=${GHCR_REPO}-buildcache:${TARGET},mode=max,compression=zstd,compression-level=9,force-compression=true,oci-mediatypes=true,image-manifest=false"
  ]
  context = "./"
  dockerfile = "Dockerfile.build"
  output = ["./artifact"]
}
target "image" {
  inherits = ["build","docker-metadata-action"]
  cache-to = [""]
  cache-from = [
    "type=registry,ref=${GHCR_REPO}-buildcache:${TARGET}"
  ]
  target = equal("", "${SUFFIX}") ? "gnu" : "musl"
  platforms = [
    "${DOCKER_PLATFORM}"
  ]
  output = [
    ""
  ]
}
