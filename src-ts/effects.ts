// Always-on WebGL2/WebGL1 Simplex+FBM Aurora Shader + Crisp Snowfall Renderer
// Respects prefers-reduced-motion (renders static frame instead of hiding) and low-end GPUs.

const VERTEX_GL2 = `#version 300 es
in vec2 a_position;
void main() {
  gl_Position = vec4(a_position, 0.0, 1.0);
}`;

const FRAGMENT_GL2 = `#version 300 es
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
}`;

const VERTEX_GL1 = `
attribute vec2 a_position;
void main() { gl_Position = vec4(a_position, 0.0, 1.0); }`;

const FRAGMENT_GL1 = FRAGMENT_GL2.replace("#version 300 es\n", "")
  .replace("out vec4 outColor;\n", "")
  .replace(/outColor = /g, "gl_FragColor = ");

function compileShader(
  gl: WebGLRenderingContext | WebGL2RenderingContext,
  type: number,
  source: string,
): WebGLShader | null {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}

function initShader(reducedMotion: boolean): void {
  const canvas = document.getElementById("bg-shader-canvas") as HTMLCanvasElement | null;
  if (!canvas) return;

  const gl2 = canvas.getContext("webgl2", {
    alpha: false,
    antialias: false,
    powerPreference: "low-power",
  });
  const gl1 = gl2
    ? null
    : canvas.getContext("webgl", {
        alpha: false,
        antialias: false,
        powerPreference: "low-power",
      });

  const gl = gl2 ?? gl1;
  if (!gl) return;

  const isGl2 = Boolean(gl2);
  const vs = compileShader(gl, gl.VERTEX_SHADER, isGl2 ? VERTEX_GL2 : VERTEX_GL1);
  const fs = compileShader(gl, gl.FRAGMENT_SHADER, isGl2 ? FRAGMENT_GL2 : FRAGMENT_GL1);
  if (!vs || !fs) return;

  const program = gl.createProgram();
  if (!program) return;
  gl.attachShader(program, vs);
  gl.attachShader(program, fs);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    gl.deleteProgram(program);
    return;
  }

  const buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(
    gl.ARRAY_BUFFER,
    new Float32Array([-1, -1, 1, -1, -1, 1, -1, 1, 1, -1, 1, 1]),
    gl.STATIC_DRAW,
  );

  const posLoc = gl.getAttribLocation(program, "a_position");
  const timeLoc = gl.getUniformLocation(program, "u_time");
  const resLoc = gl.getUniformLocation(program, "u_resolution");
  const mouseLoc = gl.getUniformLocation(program, "u_mouse");

  gl.useProgram(program);
  gl.enableVertexAttribArray(posLoc);
  gl.vertexAttribPointer(posLoc, 2, gl.FLOAT, false, 0, 0);

  const lowEnd =
    (typeof navigator.hardwareConcurrency === "number" && navigator.hardwareConcurrency <= 4) ||
    window.innerWidth < 768;
  const maxDpr = lowEnd ? 1 : 1.5;
  const minFrameMs = lowEnd ? 33.3 : 16.6;

  const resize = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, maxDpr);
    const w = Math.max(1, Math.floor(window.innerWidth * dpr));
    const h = Math.max(1, Math.floor(window.innerHeight * dpr));
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w;
      canvas.height = h;
    }
    gl.viewport(0, 0, canvas.width, canvas.height);
  };
  resize();
  window.addEventListener("resize", resize);

  let mouseX = 0.5;
  let mouseY = 0.5;
  window.addEventListener(
    "pointermove",
    (e: PointerEvent) => {
      const nx = e.clientX / Math.max(1, window.innerWidth);
      const ny = 1 - e.clientY / Math.max(1, window.innerHeight);
      if (Number.isFinite(nx) && Number.isFinite(ny)) {
        mouseX = Math.min(1, Math.max(0, nx));
        mouseY = Math.min(1, Math.max(0, ny));
      }
    },
    { passive: true },
  );

  const drawFrame = (tSec: number) => {
    gl.useProgram(program);
    gl.uniform1f(timeLoc, tSec);
    gl.uniform2f(resLoc, canvas.width, canvas.height);
    gl.uniform2f(mouseLoc, mouseX, mouseY);
    gl.drawArrays(gl.TRIANGLES, 0, 6);
  };

  if (reducedMotion) {
    drawFrame(3.2);
    window.addEventListener("resize", () => drawFrame(3.2));
    return;
  }

  const startTime = performance.now();
  let lastFrame = 0;

  const loop = (now: number) => {
    if (!document.hidden && now - lastFrame >= minFrameMs) {
      lastFrame = now;
      drawFrame((now - startTime) * 0.001);
    }
    requestAnimationFrame(loop);
  };
  requestAnimationFrame(loop);
}

function drawCrystalFlake(ctx: CanvasRenderingContext2D, r: number): void {
  ctx.strokeStyle = "rgba(255, 255, 255, 0.92)";
  ctx.lineWidth = Math.max(1, r * 0.14);
  ctx.lineCap = "round";
  for (let i = 0; i < 6; i++) {
    ctx.save();
    ctx.rotate((i * Math.PI) / 3);
    ctx.beginPath();
    ctx.moveTo(0, 0);
    ctx.lineTo(0, -r);
    ctx.moveTo(0, -r * 0.55);
    ctx.lineTo(-r * 0.25, -r * 0.78);
    ctx.moveTo(0, -r * 0.55);
    ctx.lineTo(r * 0.25, -r * 0.78);
    ctx.stroke();
    ctx.restore();
  }
}

function initSnowfall(reducedMotion: boolean): void {
  const canvas = document.getElementById("snow-canvas") as HTMLCanvasElement | null;
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  const img = new Image();
  let imgLoaded = false;
  img.onload = () => {
    imgLoaded = true;
  };
  img.src = "./assets/img/snowflake.png";

  const resize = () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  };
  resize();
  window.addEventListener("resize", resize);

  const lowEnd = typeof navigator.hardwareConcurrency === "number" && navigator.hardwareConcurrency <= 4;
  const count = lowEnd || window.innerWidth < 768 ? 24 : 44;

  const flakes = Array.from({ length: count }, () => ({
    x: Math.random() * canvas.width,
    y: Math.random() * canvas.height,
    size: 10 + Math.random() * 14,
    vy: 0.5 + Math.random() * 1.05,
    vx: (Math.random() - 0.5) * 0.4,
    phase: Math.random() * Math.PI * 2,
    rot: Math.random() * Math.PI * 2,
    vrot: (Math.random() - 0.5) * 0.022,
    alpha: 0.42 + Math.random() * 0.5,
  }));

  const drawAll = (animate: boolean) => {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const f of flakes) {
      if (animate) {
        f.phase += 0.015;
        f.y += f.vy;
        f.x += f.vx + Math.sin(f.phase) * 0.38;
        f.rot += f.vrot;

        if (f.y > canvas.height + f.size) {
          f.y = -f.size;
          f.x = Math.random() * canvas.width;
        }
        if (f.x > canvas.width + f.size) f.x = -f.size;
        if (f.x < -f.size) f.x = canvas.width + f.size;
      }

      ctx.save();
      ctx.globalAlpha = f.alpha;
      ctx.translate(f.x, f.y);
      ctx.rotate(f.rot);
      if (imgLoaded) {
        ctx.drawImage(img, -f.size / 2, -f.size / 2, f.size, f.size);
      } else {
        drawCrystalFlake(ctx, f.size * 0.48);
      }
      ctx.restore();
    }
  };

  if (reducedMotion) {
    drawAll(false);
    img.onload = () => {
      imgLoaded = true;
      drawAll(false);
    };
    return;
  }

  let lastFrame = 0;
  const minFrameMs = lowEnd ? 33.3 : 16.6;

  const loop = (now: number) => {
    if (!document.hidden && now - lastFrame >= minFrameMs) {
      lastFrame = now;
      drawAll(true);
    }
    requestAnimationFrame(loop);
  };
  requestAnimationFrame(loop);
}

function enhanceSelect(select: HTMLSelectElement): void {
  if (select.dataset.enhanced === "true") return;
  select.dataset.enhanced = "true";

  const wrap = document.createElement("div");
  wrap.className = "c-select";
  if (select.style.width) {
    wrap.style.width = select.style.width;
  }

  select.parentNode?.insertBefore(wrap, select);
  select.classList.add("c-select-native");
  wrap.appendChild(select);

  const trigger = document.createElement("button");
  trigger.type = "button";
  trigger.className = "c-select-trigger";

  const labelSpan = document.createElement("span");
  const svgNs = "http://www.w3.org/2000/svg";
  const arrow = document.createElementNS(svgNs, "svg");
  arrow.setAttribute("class", "c-select-arrow");
  arrow.setAttribute("viewBox", "0 0 24 24");
  arrow.setAttribute("fill", "none");
  arrow.setAttribute("stroke", "currentColor");
  arrow.setAttribute("stroke-width", "2");
  const poly = document.createElementNS(svgNs, "polyline");
  poly.setAttribute("points", "6 9 12 15 18 9");
  arrow.appendChild(poly);

  trigger.append(labelSpan, arrow);

  const menu = document.createElement("div");
  menu.className = "c-select-menu hidden";
  wrap.append(trigger, menu);

  const syncOptions = () => {
    menu.replaceChildren();
    const opts = Array.from(select.options);
    const activeOpt = opts[select.selectedIndex] ?? opts[0];
    labelSpan.textContent = activeOpt ? activeOpt.textContent : "—";

    opts.forEach((opt) => {
      const item = document.createElement("div");
      item.className = `c-select-option${opt.value === select.value ? " selected" : ""}`;
      item.textContent = opt.textContent;
      item.addEventListener("click", () => {
        select.value = opt.value;
        select.dispatchEvent(new Event("change", { bubbles: true }));
        menu.classList.add("hidden");
        wrap.classList.remove("open");
        syncOptions();
      });
      menu.appendChild(item);
    });
  };

  syncOptions();

  trigger.addEventListener("click", (e) => {
    e.stopPropagation();
    const isOpen = wrap.classList.contains("open");
    document.querySelectorAll(".c-select.open").forEach((el) => {
      el.classList.remove("open");
      el.querySelector(".c-select-menu")?.classList.add("hidden");
    });
    if (!isOpen) {
      wrap.classList.add("open");
      menu.classList.remove("hidden");
    }
  });

  select.addEventListener("change", syncOptions);

  const observer = new MutationObserver(syncOptions);
  observer.observe(select, { childList: true });
}

function initCustomSelects(): void {
  document.querySelectorAll<HTMLSelectElement>("select").forEach(enhanceSelect);
  document.addEventListener("click", () => {
    document.querySelectorAll(".c-select.open").forEach((el) => {
      el.classList.remove("open");
      el.querySelector(".c-select-menu")?.classList.add("hidden");
    });
  });
}

function bootVisuals(): void {
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  initShader(reducedMotion);
  initSnowfall(reducedMotion);
  initCustomSelects();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootVisuals);
} else {
  bootVisuals();
}
