package s3client

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/minio/minio-go"
	"whalebone.io/serve-file/config"
)

type S3Client interface {
	GetObjectWithContext(ctx context.Context, objectName string, opts minio.GetObjectOptions) (*minio.Object, error)
}

type s3ClientImpl struct {
	client       *minio.Client
	bucketName   string
	dataFileTmpl string
}

func New(endpoint, accessKey, secretKey, bucketName, dataFileTmpl string, unsecureConn bool, settings *config.Settings) (S3Client, error) {
	s3Client, err := minio.New(endpoint, accessKey, secretKey, !unsecureConn)
	if err != nil {
		return nil, err
	}
	if settings.S3_USE_OUR_CACERTPOOL {
		tr := &http.Transport{
			TLSClientConfig:    &tls.Config{RootCAs: settings.CACertPool, MinVersion: tls.VersionTLS12},
			DisableCompression: true,
		}
		s3Client.SetCustomTransport(tr)
	}

	return &s3ClientImpl{
		client:       s3Client,
		bucketName:   bucketName,
		dataFileTmpl: dataFileTmpl,
	}, nil
}

func (c *s3ClientImpl) GetObjectWithContext(ctx context.Context, objectName string, opts minio.GetObjectOptions) (*minio.Object, error) {
	return c.client.GetObjectWithContext(ctx, c.bucketName, objectName, opts)
}
