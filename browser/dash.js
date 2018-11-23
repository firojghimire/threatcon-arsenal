$(document).ready(function() {
	$.getJSON('data.json', function(data) {
		var items = [];
		items.push("<tr><th>Domain</th><th>Malicious URLs in the Domain</th><th>Web Reputation</th></tr>");
		$.each( data, function( key, val ) {
			items.push("<tr>");
			$.each(val, function(a, b){
				items.push( "<td id="+a+ ">"+ b+"</td>" );
			});
			items.push("</tr>");
		});
	console.log(items);
	$( "<table border=2>"+items.join(''), {
               "class": "list",
               }).appendTo( "body" );

       });
});
