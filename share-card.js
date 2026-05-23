/* share-card.js — reusable story-card generator (generalised from the Learn IRL
 * result card). Renders a 1080x1920-ish portrait PNG and shares via the Web Share
 * API where available, else downloads. Use for streaks, exam wins, milestones.
 * Usage: SDShareCard.share({ title, bigValue, subtitle, accent, footer }). */
(function () {
  if (window.SDShareCard) return;

  function wrap(ctx, text, maxWidth) {
    var words = String(text || '').split(' '), lines = [], line = '';
    for (var i = 0; i < words.length; i++) {
      var test = line ? line + ' ' + words[i] : words[i];
      if (ctx.measureText(test).width > maxWidth && line) { lines.push(line); line = words[i]; }
      else line = test;
    }
    if (line) lines.push(line);
    return lines;
  }

  function draw(opts) {
    var W = 1080, H = 1350;
    var accent = opts.accent || '#6C63FF';
    var canvas = document.createElement('canvas');
    canvas.width = W; canvas.height = H;
    var ctx = canvas.getContext('2d');

    // Background
    var bg = ctx.createLinearGradient(0, 0, W, H);
    bg.addColorStop(0, '#0d0b16'); bg.addColorStop(1, '#08080d');
    ctx.fillStyle = bg; ctx.fillRect(0, 0, W, H);

    // Top accent bar
    ctx.fillStyle = accent; ctx.fillRect(0, 0, W, 14);

    // Brand
    ctx.textAlign = 'center';
    ctx.fillStyle = accent;
    ctx.font = '700 44px -apple-system, Segoe UI, Roboto, sans-serif';
    ctx.fillText('STUDY DECODER', W / 2, 150);

    // Title
    ctx.fillStyle = 'rgba(255,255,255,0.72)';
    ctx.font = '600 46px -apple-system, Segoe UI, Roboto, sans-serif';
    var titleLines = wrap(ctx, opts.title || '', W - 200);
    var ty = 340;
    titleLines.forEach(function (l) { ctx.fillText(l, W / 2, ty); ty += 60; });

    // Big value
    ctx.fillStyle = '#ffffff';
    ctx.font = '800 220px -apple-system, Segoe UI, Roboto, sans-serif';
    ctx.fillText(String(opts.bigValue == null ? '' : opts.bigValue), W / 2, H / 2 + 90);

    // Subtitle
    ctx.fillStyle = 'rgba(255,255,255,0.85)';
    ctx.font = '500 50px -apple-system, Segoe UI, Roboto, sans-serif';
    var subLines = wrap(ctx, opts.subtitle || '', W - 220);
    var sy = H / 2 + 230;
    subLines.forEach(function (l) { ctx.fillText(l, W / 2, sy); sy += 64; });

    // Footer
    ctx.fillStyle = 'rgba(255,255,255,0.5)';
    ctx.font = '500 38px -apple-system, Segoe UI, Roboto, sans-serif';
    ctx.fillText(opts.footer || 'studydecoder.com.au', W / 2, H - 90);

    return canvas;
  }

  function share(opts) {
    opts = opts || {};
    var canvas = draw(opts);
    var fileName = 'study-decoder-' + (opts.kind || 'card') + '.png';
    return new Promise(function (resolve) {
      canvas.toBlob(function (blob) {
        if (!blob) { resolve(false); return; }
        var file = new File([blob], fileName, { type: 'image/png' });
        if (navigator.share && navigator.canShare && navigator.canShare({ files: [file] })) {
          navigator.share({ files: [file], title: opts.title || 'Study Decoder', text: opts.shareText || (opts.title || '') })
            .then(function () { resolve(true); })
            .catch(function () { resolve(false); });
        } else {
          var url = URL.createObjectURL(blob);
          var a = document.createElement('a');
          a.href = url; a.download = fileName; a.click();
          setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
          resolve(true);
        }
      }, 'image/png');
    });
  }

  window.SDShareCard = { share: share, draw: draw };
})();
