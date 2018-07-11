package nl.nlighten.prometheus.tomcat;


import javax.servlet.ServletConfig;
import javax.servlet.annotation.WebServlet;

import io.prometheus.client.exporter.MetricsServlet;
import io.prometheus.client.hotspot.DefaultExports;


@WebServlet("/")
public class TomcatMetricsServlet extends MetricsServlet {

    private static final long serialVersionUID = 1L;

	@Override
    public void init(ServletConfig config) {
        DefaultExports.initialize();
        new TomcatGenericExports(false).register();
        if (TomcatJdbcPoolExports.isTomcatJdbcUsed()) {
            new TomcatJdbcPoolExports().register();
        } else {
            new TomcatDbcp2PoolExports().register();
        }
    }
}


