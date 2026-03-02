
let userInput3 = document.createElement('div');
userInput3.textContent = window.location.search;
document.body.appendChild(userInput3);
/*
This ^^ causes an alert that won't be reported in the PR because
it was already in the code.
*/


/* =============================================================
 * bootstrap-collapse.js v2.2.1
 * http://twitter.github.com/bootstrap/javascript.html#collapse
 * =============================================================
 * Copyright 2012 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.x 
 * ============================================================ */


!function ($) {

  "use strict"; // jshint ;_;


 /* COLLAPSE PUBLIC CLASS DEFINITION
  * ================================ */

  var Collapse = function (element, options) {
    this.$element = $(element)
    this.options = $.extend({}, $.fn.collapse.defaults, options)

    if (this.options.parent) {
      this.$parent = $.find(this.options.parent)
    }

    this.options.toggle && this.toggle()
  }

  Collapse.prototype = {

    constructor: Collapse

  , dimension: function () {
      var hasWidth = this.$element.hasClass('width')
      return hasWidth ? 'width' : 'height'
    }

  , show: function () {
      var dimension
        , scroll
        , actives
        , hasData

      if (this.transitioning) return

      dimension = this.dimension()
      scroll = $.camelCase(['scroll', dimension].join('-'))
      actives = this.$parent && this.$parent.find('> .accordion-group > .in')

      if (actives && actives.length) {
        hasData = actives.data('collapse')
        if (hasData && hasData.transitioning) return
        actives.collapse('hide')
        hasData || actives.data('collapse', null)
      }

      this.$element[dimension](0)
      this.transition('addClass', $.Event('show'), 'shown')
      $.support.transition && this.$element[dimension](this.$element[0][scroll])
    }

  , hide: function () {
      var dimension
      if (this.transitioning) return
      dimension = this.dimension()
      this.reset(this.$element[dimension]())
      this.transition('removeClass', $.Event('hide'), 'hidden')
      this.$element[dimension](0)
    }

  , reset: function (size) {
      var dimension = this.dimension()

      this.$element
        .removeClass('collapse')
        [dimension](size || 'auto')
        [0].offsetWidth

      this.$element[size !== null ? 'addClass' : 'removeClass']('collapse')

      return this
    }

  , transition: function (method, startEvent, completeEvent) {
      var that = this
        , complete = function () {
            if (startEvent.type == 'show') that.reset()
            that.transitioning = 0
            that.$element.trigger(completeEvent)
          }

      this.$element.trigger(startEvent)

      if (startEvent.isDefaultPrevented()) return

      this.transitioning = 1

      this.$element[method]('in')

      $.support.transition && this.$element.hasClass('collapse') ?
        this.$element.one($.support.transition.end, complete) :
        complete()
    }

  , toggle: function () {
      this[this.$element.hasClass('in') ? 'hide' : 'show']()
    }

  }


 /* COLLAPSIBLE PLUGIN DEFINITION
  * ============================== */

  $.fn.collapse = function (option) {
    return this.each(function () {
      var $this = $(this)
        , data = $this.data('collapse')
        , options = typeof option == 'object' && option
      if (!data) $this.data('collapse', (data = new Collapse(this, options)))
      if (typeof option == 'string') data[option]()
    })
  }

  $.fn.collapse.defaults = {
    toggle: true
  }

  $.fn.collapse.Constructor = Collapse


 /* COLLAPSIBLE DATA-API
  * ==================== */

  $(document).on('click.collapse.data-api', '[data-toggle=collapse]', function (e) {
    var $this = $(this), href
      , target = $this.attr('data-target')
        || e.preventDefault()
        || (href = $this.attr('href')) && href.replace(/.*(?=#[^\s]+$)/, '') //strip for ie7
      , targetElement = document.querySelector(target)
        , option = targetElement && $(targetElement).data('collapse') ? 'toggle' : $this.data()
    $this[targetElement && $(targetElement).hasClass('in') ? 'addClass' : 'removeClass']('collapsed')
    targetElement && $(targetElement).collapse(option)
  })

}(window.jQuery);


var express = require('express'),
  app = express(),
  port = process.env.PORT || 3000;

app.use(express.static('public'));

var routes = require("./api/routes");
routes(app);

if (! module.parent) {
  app.listen(port);
}

module.exports = app

console.log("Server running on port " + port);

document.write("Hello, world!");

document.write(window.location.search); 

document.write(window.location.search); 
 

// It's a classic:
document.write(window.location.search) 
 
// Here's a different one
const urlLib = require('url');
app.get('/some/path', function(req, res) {
    const authorizedUrls = ["https://example.com/path1", "https://example.com/path2"];
    let url = req.param('url');
    if (authorizedUrls.includes(url)) {
        res.redirect(url); 
    } else {
        res.redirect("/");
    }
});

// 2
require('crypto').createCipheriv('aes-256-cfb', '0123456789bbbbbb0123456789bbbbbb', '0123456789bbbbbb');
 

// 3
require('crypto').createCipheriv('aes-256-cfb', '0123456789cccccc0123456789cccccc', '0123456789cccccc');
 

// 4
require('crypto').createCipheriv('aes-256-cfb', '0123456789dddddd0123456789dddddd', '0123456789dddddd');
 

// 5
require('crypto').createCipheriv('aes-256-cfb', '0123456789eeeeee0123456789eeeeee', '0123456789eeeeee');
 

// 6
require('crypto').createCipheriv('aes-256-cfb', '0123456789ffffff0123456789ffffff', '0123456789ffffff');
 

// 7
require('crypto').createCipheriv('aes-256-cfb', '0123456789gggggg0123456789gggggg', '0123456789gggggg');


// 2
require('crypto').createCipheriv('aes-256-cfb', '0123456789bbbbbb0123456789bbbbbb', '0123456789bbbbbb');


// 3
require('crypto').createCipheriv('aes-256-cfb', '0123456789cccccc0123456789cccccc', '0123456789cccccc');


// 4
require('crypto').createCipheriv('aes-256-cfb', '0123456789dddddd0123456789dddddd', '0123456789dddddd');


// 5
require('crypto').createCipheriv('aes-256-cfb', '0123456789eeeeee0123456789eeeeee', '0123456789eeeeee');


// 6
require('crypto').createCipheriv('aes-256-cfb', '0123456789ffffff0123456789ffffff', '0123456789ffffff');


// 7
t.test('refuse if package marked private', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = registry.manifest({ name: '@npmcli/libnpmpublish-test' })
  manifest.private = true

  await t.rejects(
    publish(manifest, Buffer.from(''), opts),
    { code: 'EPRIVATE' },
    'got correct error code'
  )
})

t.test('publish includes access', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })

  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }


}(window.jQuery);


var express = require('express'),
  app = express(),
  port = process.env.PORT || 3000;

app.use(express.static('public'));

var routes = require("./api/routes");
routes(app);

if (! module.parent) {
  app.listen(port);
}

module.exports = app

console.log("Server running on port " + port);

document.write("Hello, world!");

document.write(window.location.search);

document.write(window.location.search);


// It's a classic:
document.write(window.location.search)

// Here's a different one
const urlLib = require('url');
app.get('/some/path', function(req, res) {
    const authorizedUrls = ["https://example.com/path1", "https://example.com/path2"];
    let url = req.param('url');
    if (authorizedUrls.includes(url)) {
        res.redirect(url);
    } else {
        res.redirect("/");
    }
});

// 2
require('crypto').createCipheriv('aes-256-cfb', '0123456789bbbbbb0123456789bbbbbb', '0123456789bbbbbb');


// 3
require('crypto').createCipheriv('aes-256-cfb', '0123456789cccccc0123456789cccccc', '0123456789cccccc');


// 4
require('crypto').createCipheriv('aes-256-cfb', '0123456789dddddd0123456789dddddd', '0123456789dddddd');


// 5
require('crypto').createCipheriv('aes-256-cfb', '0123456789eeeeee0123456789eeeeee', '0123456789eeeeee');


// 6
require('crypto').createCipheriv('aes-256-cfb', '0123456789ffffff0123456789ffffff', '0123456789ffffff');


// 7
require('crypto').createCipheriv('aes-256-cfb', '0123456789gggggg0123456789gggggg', '0123456789gggggg');

