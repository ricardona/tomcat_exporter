package nl.nlighten.prometheus.tomcat;

import io.prometheus.client.*;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.io.IOException;

/**
 * A servlet filter that can be configured in Tomcat's global web.xml and that provides the following metrics:
 *
 * - A Histogram with response time distribution per context
 * - A Gauge with the number of concurrent request per context
 * - A Gauge with a the number of responses per context and status code
 *
 * <p>
 * If you are running Tomcat in the conventional non-embedded way you should add the client_tomcat jar and all its
 * dependencies (see POM.XML) to the $CATALINA_BASE/lib directory or another directory on the common.loader path.
 * Next, add this filter to the $CATALINA_BASE/lib/web.xml, e.g.:
 *
 * <pre>
 * {@code
 * <filter>
 *   <filter-name>ServletMetricsFilter</filter-name>
 *   <filter-class>nl.nlighten.prometheus.TomcatServletMetricsFilter</filter-class>
 *   <async-supported>true</async-supported>
 *   <init-param>
 *     <param-name>buckets</param-name>
 *     <param-value>.01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30</param-value>
 *   </init-param>
 * </filter>
 * }
 * </pre>
 *
 * If you running Tomcat embedded, please check AbstractTomcatMetricsTest for example configuration.
 *
 * Example metrics being exported:
 * <pre>
 *     servlet_request_seconds_bucket{"/foo", "GET", "0.1",} 1.0
 *     ....
 *     servlet_request_seconds_bucket{"/foo", "GET", "+Inf",} 1.0
 *     servlet_request_concurrent_total{"/foo",} 1.0
 *     servlet_response_status_total{"/foo", "200",} 1.0
 *  </pre>
 */
public class TomcatServletMetricsFilter implements Filter {
	private static final String BUCKET_CONFIG_PARAM = "buckets";
    private static Histogram servletLatency;
    private static Gauge servletConcurrentRequest;
    private static Gauge servletStatusCodes;
    private static Gauge servletUserRequest;

    private static int UNDEFINED_HTTP_STATUS = 999;
    private static final String AUTH_HEADER = "Authorization";
    private static final String TOKEN_USER_KEY = "userid";
    private static final String ANONYMOUS_USER = "Anonymous";

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        if (servletLatency == null) {
            Histogram.Builder servletLatencyBuilder = Histogram.build()
                    .name("servlet_request_seconds")
                    .help("The time taken fulfilling servlet requests")
                    .labelNames("context", "uri", "query", "method");

            if ((filterConfig.getInitParameter(BUCKET_CONFIG_PARAM) != null) && (!filterConfig.getInitParameter(BUCKET_CONFIG_PARAM).isEmpty())) {
                String[] bucketParams = filterConfig.getInitParameter(BUCKET_CONFIG_PARAM).split(",");
                double[] buckets = new double[bucketParams.length];
                for (int i = 0; i < bucketParams.length; i++) {
                    buckets[i] = Double.parseDouble(bucketParams[i].trim());
                }
                servletLatencyBuilder.buckets(buckets);
            } else {
                servletLatencyBuilder.buckets(.01, .05, .1, .25, .5, 1, 2.5, 5, 10, 30);
            }

            servletLatency = servletLatencyBuilder.register();

            Gauge.Builder servletConcurrentRequestBuilder = Gauge.build()
                    .name("servlet_request_concurrent_total")
                    .help("Number of concurrent requests for given context.")
                    .labelNames("context");

            servletConcurrentRequest = servletConcurrentRequestBuilder.register();

            Gauge.Builder servletStatusCodesBuilder = Gauge.build()
                    .name("servlet_response_status_total")
                    .help("Number of requests for given context and status code.")
                    .labelNames("context", "uri", "query", "status");

            servletStatusCodes = servletStatusCodesBuilder.register();

            Gauge.Builder servletUserRequestBuilder = Gauge.build()
                    .name("servlet_user_request_total")
                    .help("Number of requests for given user.")
                    .labelNames("context", "uri", "user", "status");

            servletUserRequest = servletUserRequestBuilder.register();
        }
    }



    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        if (!(servletRequest instanceof HttpServletRequest)) {
            filterChain.doFilter(servletRequest, servletResponse);
            return;
        }

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        String context = getContext(request);

        if (!request.isAsyncStarted() && context.startsWith("/openintl")) {            
            String uri = getURI(request);
            String query = getQuery(request);
            String user = getUser(request);
            String status = Integer.toString(getStatus((HttpServletResponse) servletResponse));
            String clientIPAddress = getClientIPAddress(request);

            servletConcurrentRequest.labels(context).inc();

            Histogram.Timer timer = servletLatency
                    .labels(context, uri, query, request.getMethod())
                    .startTimer();

            try {
                filterChain.doFilter(servletRequest, servletResponse);
            } finally {
                timer.observeDuration();
                servletConcurrentRequest.labels(context).dec();

				servletStatusCodes.labels(context, uri, query, status).inc();
                servletUserRequest.labels(context, uri, user, status).inc();
            }
        } else {
            filterChain.doFilter(servletRequest, servletResponse);
        }
    }


    /**
     * Get user real IP behind reverse proxy
     * 
     * Behind a reverse proxy, the user IP we get is often the reverse proxy IP itself. 
     * But for obvious reasons it’s important to have access to the user real ip address.
     *  
     * We need to tell the reverse proxy to pass information to the backend nginx server.
     * We can add to the nginx thoses lines as a global configuration or per location.
     * 
     *   proxy_set_header X-Real-IP $remote_addr;
     *   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
     *   proxy_set_header X-Forwarded-Proto $proxy_x_forwarded_proto;
     */
	private String getClientIPAddress(HttpServletRequest request) {
        String clientIPAddress = request.getHeader("X-REAL-IP");

            if (clientIPAddress == null) {
              clientIPAddress = request.getHeader("X-FORWARDED-FOR");
            }

            if (clientIPAddress == null) {
                clientIPAddress = request.getRemoteAddr();
            }

        return clientIPAddress;
	}

    private String getUserFromJwt(String token){
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim(TOKEN_USER_KEY).asString();
        } catch (JWTDecodeException exception){
            return ANONYMOUS_USER;
        }
    }

    private String getUser(HttpServletRequest request) {
        String header = request.getHeader(AUTH_HEADER);
		if (header != null && !header.isEmpty()) {
            String userFromJwt = getUserFromJwt(header);
			return userFromJwt;
        } else {
            return ANONYMOUS_USER;
        }
	}

	private int getStatus(HttpServletResponse response) {
        try {
            return response.getStatus();
        } catch (Exception ex) {
            return UNDEFINED_HTTP_STATUS;
        }
    }

    private String getContext(HttpServletRequest request) {
        if (request.getContextPath() != null && !request.getContextPath().isEmpty()) {
            return request.getContextPath();
        } else {
            return "/";
        }
    }

    private String getURI(HttpServletRequest request) {
        if (request.getRequestURI() != null && !request.getRequestURI().isEmpty()) {
            return request.getRequestURI();
        } else {
            return "";
        }
    }

    private String getQuery(HttpServletRequest request) {
        if (request.getQueryString() != null && !request.getQueryString().isEmpty()) {
            return request.getQueryString();
        } else {
            return "";
        }
    }

    @Override
    public void destroy() {
        // NOOP
    }
}