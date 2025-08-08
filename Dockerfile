FROM golang:1.24-bullseye AS build
RUN apt-get update && apt-get install -y gcc
WORKDIR /app
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o server .

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /app/server /app/
COPY --from=build /app/templates /app/templates
EXPOSE 8080
CMD ["/app/server"]
