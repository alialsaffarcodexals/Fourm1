FROM golang:1.22 AS build
WORKDIR /app
COPY . .
RUN go build -o server .

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /app/server /app/
COPY --from=build /app/templates /app/templates
EXPOSE 8080
CMD ["/app/server"]
