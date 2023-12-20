FROM golang:1.21 AS build
WORKDIR /go/src/sgp
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o simplegoproxy -ldflags "-s -w" .

FROM alpine:latest  
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=build /go/src/sgp/simplegoproxy .
RUN chmod a+x /app/simplegoproxy
EXPOSE 3000
CMD ["/app/simplegoproxy"]
