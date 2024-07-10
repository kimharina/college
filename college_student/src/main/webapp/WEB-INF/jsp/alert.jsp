<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>

<c:choose>
	<c:when test="${empty url }">
		<script type="text/javascript">
			alert("${alert}")
			self.close()
		</script>
	</c:when>
	<c:otherwise>
		<script type="text/javascript">
			alert("${alert}")
			location.href="${url}"
		</script>
	</c:otherwise>
</c:choose>







