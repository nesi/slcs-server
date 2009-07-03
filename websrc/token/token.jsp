<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
    <head>
    </head>
    <body>
    	<img src="/SLCS/images/arcs-logo.png" alt="ARCS Logo" />
        <h1>SLCS Certificate Request</h1>
        <form id="token" method="post" action="<%=request.getAttribute("serviceUrl")%>">
        	<p>Do you authorise <%=request.getAttribute("serviceUrl")%> to generate a certificate on your behalf?</p>
            <div>
                <input type="hidden" name="SessionKey" value="<%=request.getAttribute("encSessionKey")%>"/>
                <input type="hidden" name="CertificateRequestData" value="<%=request.getAttribute("encMessage")%>"/>
                <input type="submit" value="Authorise >>"/>
            </div>
        </form>
    </body>
</html>