"use strict";(()=>{var z=`#version 300 es
in vec2 a_position;
void main() {
  gl_Position = vec4(a_position, 0.0, 1.0);
}`,A=`#version 300 es
precision mediump float;
uniform float u_time;
uniform vec2 u_resolution;
uniform vec2 u_mouse;
out vec4 outColor;

vec3 mod289(vec3 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
vec2 mod289(vec2 x) { return x - floor(x * (1.0 / 289.0)) * 289.0; }
vec3 permute(vec3 x) { return mod289(((x * 34.0) + 1.0) * x); }

float snoise(vec2 v) {
  const vec4 C = vec4(0.211324865405187, 0.366025403784439, -0.577350269189626, 0.024390243902439);
  vec2 i = floor(v + dot(v, C.yy));
  vec2 x0 = v - i + dot(i, C.xx);
  vec2 i1 = (x0.x > x0.y) ? vec2(1.0, 0.0) : vec2(0.0, 1.0);
  vec4 x12 = x0.xyxy + C.xxzz;
  x12.xy -= i1;
  i = mod289(i);
  vec3 p = permute(permute(i.y + vec3(0.0, i1.y, 1.0)) + i.x + vec3(0.0, i1.x, 1.0));
  vec3 m = max(0.5 - vec3(dot(x0, x0), dot(x12.xy, x12.xy), dot(x12.zw, x12.zw)), 0.0);
  m = m * m;
  m = m * m;
  vec3 x = 2.0 * fract(p * C.www) - 1.0;
  vec3 h = abs(x) - 0.5;
  vec3 ox = floor(x + 0.5);
  vec3 a0 = x - ox;
  m *= 1.79284291400159 - 0.85373472095314 * (a0 * a0 + h * h);
  vec3 g;
  g.x = a0.x * x0.x + h.x * x0.y;
  g.yz = a0.yz * x12.xz + h.yz * x12.yw;
  return 130.0 * dot(m, g);
}

float fbm(vec2 p) {
  float value = 0.0;
  float amplitude = 0.5;
  mat2 rot = mat2(0.80, 0.60, -0.60, 0.80);
  for (int i = 0; i < 4; i++) {
    value += amplitude * (snoise(p) * 0.5 + 0.5);
    p = rot * p * 2.02 + vec2(17.1, 31.7);
    amplitude *= 0.5;
  }
  return value;
}

void main() {
  vec2 uv = gl_FragCoord.xy / max(u_resolution, vec2(1.0));
  float aspect = u_resolution.x / max(u_resolution.y, 1.0);
  vec2 parallax = (u_mouse - 0.5) * 0.12;
  vec2 st = vec2((uv.x - 0.5) * aspect + 0.5, uv.y) + parallax;

  float slowTime = u_time * 0.13;
  vec2 warp = vec2(
    fbm(st * 1.45 + vec2(slowTime * 0.7, -slowTime * 0.4)),
    fbm(st * 1.45 + vec2(-slowTime * 0.5, slowTime * 0.6) + 5.2)
  );

  float n = fbm(st * 2.15 + warp * 0.72 + vec2(slowTime, slowTime * 0.45));
  float ribbon = smoothstep(0.28, 0.76, n);
  float breath = 0.90 + 0.10 * sin(u_time * 0.5);
  float intensity = pow(ribbon, 1.2) * 0.64 * breath;

  float dist = length(uv - vec2(0.5));
  float vignette = smoothstep(0.0, 1.0, clamp(1.08 - dist * 1.08, 0.0, 1.0));

  vec3 baseColor = vec3(0.028, 0.029, 0.035);
  vec3 glowTint = vec3(0.90, 0.93, 1.0) * (intensity * vignette);
  outColor = vec4(baseColor + glowTint, 1.0);
}`,F=`
attribute vec2 a_position;
void main() { gl_Position = vec4(a_position, 0.0, 1.0); }`,P=A.replace(`#version 300 es
`,"").replace(`out vec4 outColor;
`,"").replace(/outColor = /g,"gl_FragColor = ");function C(e,t,a){let r=e.createShader(t);return r?(e.shaderSource(r,a),e.compileShader(r),e.getShaderParameter(r,e.COMPILE_STATUS)?r:(e.deleteShader(r),null)):null}function R(e){let t=document.getElementById("bg-shader-canvas");if(!t)return;let a=t.getContext("webgl2",{alpha:!1,antialias:!1,powerPreference:"low-power"}),r=a?null:t.getContext("webgl",{alpha:!1,antialias:!1,powerPreference:"low-power"}),o=a??r;if(!o)return;let s=!!a,v=C(o,o.VERTEX_SHADER,s?z:F),c=C(o,o.FRAGMENT_SHADER,s?A:P);if(!v||!c)return;let i=o.createProgram();if(!i)return;if(o.attachShader(i,v),o.attachShader(i,c),o.linkProgram(i),!o.getProgramParameter(i,o.LINK_STATUS)){o.deleteProgram(i);return}let f=o.createBuffer();o.bindBuffer(o.ARRAY_BUFFER,f),o.bufferData(o.ARRAY_BUFFER,new Float32Array([-1,-1,1,-1,-1,1,-1,1,1,-1,1,1]),o.STATIC_DRAW);let l=o.getAttribLocation(i,"a_position"),h=o.getUniformLocation(i,"u_time"),d=o.getUniformLocation(i,"u_resolution"),m=o.getUniformLocation(i,"u_mouse");o.useProgram(i),o.enableVertexAttribArray(l),o.vertexAttribPointer(l,2,o.FLOAT,!1,0,0);let n=typeof navigator.hardwareConcurrency=="number"&&navigator.hardwareConcurrency<=4||window.innerWidth<768,T=n?1:1.5,S=n?33.3:16.6,g=()=>{let u=Math.min(window.devicePixelRatio||1,T),p=Math.max(1,Math.floor(window.innerWidth*u)),w=Math.max(1,Math.floor(window.innerHeight*u));(t.width!==p||t.height!==w)&&(t.width=p,t.height=w),o.viewport(0,0,t.width,t.height)};g(),window.addEventListener("resize",g);let b=.5,y=.5;window.addEventListener("pointermove",u=>{let p=u.clientX/Math.max(1,window.innerWidth),w=1-u.clientY/Math.max(1,window.innerHeight);Number.isFinite(p)&&Number.isFinite(w)&&(b=Math.min(1,Math.max(0,p)),y=Math.min(1,Math.max(0,w)))},{passive:!0});let x=u=>{o.useProgram(i),o.uniform1f(h,u),o.uniform2f(d,t.width,t.height),o.uniform2f(m,b,y),o.drawArrays(o.TRIANGLES,0,6)};if(e){x(3.2),window.addEventListener("resize",()=>x(3.2));return}let _=performance.now(),E=0,L=u=>{!document.hidden&&u-E>=S&&(E=u,x((u-_)*.001)),requestAnimationFrame(L)};requestAnimationFrame(L)}function N(e,t){e.strokeStyle="rgba(255, 255, 255, 0.92)",e.lineWidth=Math.max(1,t*.14),e.lineCap="round";for(let a=0;a<6;a++)e.save(),e.rotate(a*Math.PI/3),e.beginPath(),e.moveTo(0,0),e.lineTo(0,-t),e.moveTo(0,-t*.55),e.lineTo(-t*.25,-t*.78),e.moveTo(0,-t*.55),e.lineTo(t*.25,-t*.78),e.stroke(),e.restore()}function G(e){let t=document.getElementById("snow-canvas");if(!t)return;let a=t.getContext("2d");if(!a)return;let r=new Image,o=!1;r.onload=()=>{o=!0},r.src="./assets/img/snowflake.png";let s=()=>{t.width=window.innerWidth,t.height=window.innerHeight};s(),window.addEventListener("resize",s);let v=typeof navigator.hardwareConcurrency=="number"&&navigator.hardwareConcurrency<=4,c=v||window.innerWidth<768?24:44,i=Array.from({length:c},()=>({x:Math.random()*t.width,y:Math.random()*t.height,size:10+Math.random()*14,vy:.5+Math.random()*1.05,vx:(Math.random()-.5)*.4,phase:Math.random()*Math.PI*2,rot:Math.random()*Math.PI*2,vrot:(Math.random()-.5)*.022,alpha:.42+Math.random()*.5})),f=m=>{a.clearRect(0,0,t.width,t.height);for(let n of i)m&&(n.phase+=.015,n.y+=n.vy,n.x+=n.vx+Math.sin(n.phase)*.38,n.rot+=n.vrot,n.y>t.height+n.size&&(n.y=-n.size,n.x=Math.random()*t.width),n.x>t.width+n.size&&(n.x=-n.size),n.x<-n.size&&(n.x=t.width+n.size)),a.save(),a.globalAlpha=n.alpha,a.translate(n.x,n.y),a.rotate(n.rot),o?a.drawImage(r,-n.size/2,-n.size/2,n.size,n.size):N(a,n.size*.48),a.restore()};if(e){f(!1),r.onload=()=>{o=!0,f(!1)};return}let l=0,h=v?33.3:16.6,d=m=>{!document.hidden&&m-l>=h&&(l=m,f(!0)),requestAnimationFrame(d)};requestAnimationFrame(d)}function I(e){if(e.dataset.enhanced==="true")return;e.dataset.enhanced="true";let t=document.createElement("div");t.className="c-select",e.style.width&&(t.style.width=e.style.width),e.parentNode?.insertBefore(t,e),e.classList.add("c-select-native"),t.appendChild(e);let a=document.createElement("button");a.type="button",a.className="c-select-trigger";let r=document.createElement("span"),o="http://www.w3.org/2000/svg",s=document.createElementNS(o,"svg");s.setAttribute("class","c-select-arrow"),s.setAttribute("viewBox","0 0 24 24"),s.setAttribute("fill","none"),s.setAttribute("stroke","currentColor"),s.setAttribute("stroke-width","2");let v=document.createElementNS(o,"polyline");v.setAttribute("points","6 9 12 15 18 9"),s.appendChild(v),a.append(r,s);let c=document.createElement("div");c.className="c-select-menu hidden",t.append(a,c);let i=()=>{c.replaceChildren();let l=Array.from(e.options),h=l[e.selectedIndex]??l[0];r.textContent=h?h.textContent:"\u2014",l.forEach(d=>{let m=document.createElement("div");m.className=`c-select-option${d.value===e.value?" selected":""}`,m.textContent=d.textContent,m.addEventListener("click",()=>{e.value=d.value,e.dispatchEvent(new Event("change",{bubbles:!0})),c.classList.add("hidden"),t.classList.remove("open"),i()}),c.appendChild(m)})};i(),a.addEventListener("click",l=>{l.stopPropagation();let h=t.classList.contains("open");document.querySelectorAll(".c-select.open").forEach(d=>{d.classList.remove("open"),d.querySelector(".c-select-menu")?.classList.add("hidden")}),h||(t.classList.add("open"),c.classList.remove("hidden"))}),e.addEventListener("change",i),new MutationObserver(i).observe(e,{childList:!0})}function k(){document.querySelectorAll("select").forEach(I),document.addEventListener("click",()=>{document.querySelectorAll(".c-select.open").forEach(e=>{e.classList.remove("open"),e.querySelector(".c-select-menu")?.classList.add("hidden")})})}function M(){let e=window.matchMedia("(prefers-reduced-motion: reduce)").matches;R(e),G(e),k()}document.readyState==="loading"?document.addEventListener("DOMContentLoaded",M):M();})();
