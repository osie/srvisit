﻿	function getXmlHttp(){
		var xmlhttp;
		try {
			xmlhttp = new ActiveXObject("Msxml2.XMLHTTP");
			} catch (e) {
			try {
				xmlhttp = new ActiveXObject("Microsoft.XMLHTTP");
				} catch (E) {
					xmlhttp = false;
					}
				}
		if (!xmlhttp && typeof XMLHttpRequest!='undefined') {
			xmlhttp = new XMLHttpRequest();
			}
		return xmlhttp;
	}
	
	function loadMenu(){
		for(i = menu.length - 1; i >= 0; i--){
			var newA = document.createElement('a');
			newA.setAttribute('href', menu[i].Link);
			newA.innerHTML = menu[i].Capt;
			
			document.getElementById('menu').appendChild(newA);
		}
	}
			
	