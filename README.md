# gin-opentracing
OpenTracing Middleware for Gin

## API
```
import (
	tracer "github.com/jtejido/gin-opentracing"
	"github.com/opentracing/opentracing-go"
)


func main() {
	router := gin.New()
	router.Use(tracer.Tracer())
	router.GET("/test", func(c *gin.Context) {
		// create a child span to track operation timing.
		span, _ := opentracing.StartSpanFromContext(c, "test")
		defer span.Finish()
		// encode a image
		c.String(200, "ok!")
	})
	...
	...
}
```

## HTML

```
import (
	tracer "github.com/jtejido/gin-opentracing"
	"github.com/opentracing/opentracing-go"
)


func main() {
	router := gin.Default()
	router.Use(tracer.Tracer())
	router.LoadHTMLGlob("templates/*")

	router.GET("/index", func(c *gin.Context) {
		// render the html and trace the execution time.
		tracer.HTML(c, 200, "index.tmpl", gin.H{
			"title": "Main website",
		})
	})
	...
	...
}
```

## With Config

TracerConfig struct {
	Skipper                Skipper
	ResourceNamer          ResourceNamerFunc
	ServiceName            string
	ClientIPHeader         string
	ClientIPHeaderDisabled bool
	QueryStringRegexp      string
	QueryStringDisabled    bool
}

```

import (
	tracer "github.com/jtejido/gin-opentracing"
	"github.com/opentracing/opentracing-go"
)


func main() {
	skipper := func(c *gin.Context) bool {
		return false
	}

	resourceNamer := func(c *gin.Context) string {
		return c.HandlerName()
	}

	config := tracer.TracerConfig{
			Skipper:       skipper,
			ResourceNamer: resourceNamer,
			ServiceName: "my-api",
			ClientIPHeader: "X-API-Token",
	}

	router := gin.Default()
	router.Use(tracer.TracerWithConfig(config))
	router.GET("/test", func(c *gin.Context) {
		// create a child span to track operation timing.
		span, _ := opentracing.StartSpanFromContext(c, "test")
		defer span.Finish()
		// encode a image
		c.String(200, "ok!")
	})
	...
	...
}
```