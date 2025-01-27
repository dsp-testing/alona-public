document.write(window.location.search);
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
      this.$parent = $(this.options.parent)
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
      , option = $(target).data('collapse') ? 'toggle' : $this.data()
    $this[$(target).hasClass('in') ? 'addClass' : 'removeClass']('collapsed')
    $(target).collapse(option)
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
    let url = req.param('url'),
        host = urlLib.parse(url).host;
    // GOOD: the host of `url` is validated before redirecting
    let expectedHost = "example.com";
    if (host === expectedHost) {
        res.redirect(url);
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


'use strict'

const cloneDeep = require('lodash.clonedeep')
const crypto = require('crypto')
const fs = require('fs')
const npa = require('npm-package-arg')
const ssri = require('ssri')
const t = require('tap')

const MockRegistry = require('@npmcli/mock-registry')
const mockGlobals = require('../../../test/fixtures/mock-globals.js')

// TODO use registry.manifest (requires json date wrangling for nock)

const tarData = fs.readFileSync('./test/fixtures/npmcli-libnpmpublish-test-1.0.0.tgz')
const shasum = crypto.createHash('sha1').update(tarData).digest('hex')
const integrity = ssri.fromData(tarData, { algorithms: ['sha512'] })

const token = 'test-auth-token'
const opts = {
  npmVersion: '1.0.0-test',
  registry: 'https://mock.reg',
  '//mock.reg/:_authToken': token,
}

t.test('basic publish - no npmVersion', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: 'libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          tarball: 'http://mock.reg/libnpmpublish-test/-/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      'libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})
  const ret = await publish(manifest, tarData, {
    ...opts,
    npmVersion: null,
  })
  t.ok(ret, 'publish succeeded')
})

t.test('scoped publish', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})

  const ret = await publish(manifest, tarData, opts)
  t.ok(ret, 'publish succeeded')
})

t.test('scoped publish - restricted access', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: '@npmcli/libnpmpublish-test@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: '@npmcli/libnpmpublish-test',
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'restricted',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    access: 'restricted',
  })
  t.ok(ret, 'publish succeeded')
})

t.test('retry after a conflict', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {},
    versions: {},
    _attachments: {},
  }
  const currentPackument = cloneDeep({
    ...basePackument,
    time: {
      modified: new Date().toISOString(),
      created: new Date().toISOString(),
      '1.0.1': new Date().toISOString(),
    },
    'dist-tags': { latest: '1.0.1' },
    versions: {
      '1.0.1': {
        _id: 'libnpmpublish@1.0.1',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.1',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.1.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.1.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const newPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const mergedPackument = cloneDeep({
    ...basePackument,
    time: currentPackument.time,
    'dist-tags': { latest: '1.0.0' },
    versions: { ...currentPackument.versions, ...newPackument.versions },
    _attachments: { ...currentPackument._attachments, ...newPackument._attachments },
  })

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...currentPackument,
  })

  registry.nock.put('/libnpmpublish', body => {
    t.same(body, {
      _rev: REV,
      ...mergedPackument,
    }, 'posted packument includes _rev and a merged version')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, opts)
  t.ok(ret, 'publish succeeded')
})

t.test('retry after a conflict -- no versions on remote', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
  }
  const currentPackument = { ...basePackument }
  const newPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const mergedPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: { ...newPackument.versions },
    _attachments: { ...newPackument._attachments },
  })

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...currentPackument,
  })

  registry.nock.put('/libnpmpublish', body => {
    t.same(body, {
      _rev: REV,
      ...mergedPackument,
    }, 'posted packument includes _rev and a merged version')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, opts)

  t.ok(ret, 'publish succeeded')
})

t.test('version conflict', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {},
    versions: {},
    _attachments: {},
  }
  const newPackument = cloneDeep(Object.assign({}, basePackument, {
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: '6.13.7',
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }))

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...newPackument,
  })

  try {
    await publish(manifest, tarData, {
      ...opts,
      npmVersion: '6.13.7',
      token: 'deadbeef',
    })
  } catch (err) {
    t.equal(err.code, 'EPUBLISHCONFLICT', 'got publish conflict code')
  }
})

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

  const packument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put('/libnpmpublish', packument).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    access: 'public',
  })

  t.ok(ret, 'publish succeeded')
})

t.test('refuse if package is unscoped plus `restricted` access', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = registry.manifest({ name: 'libnpmpublish-test' })
  await t.rejects(publish(manifest, Buffer.from(''), {
    ...opts,
    access: 'restricted',
  }),
  { code: 'EUNSCOPED' }
  )
})

t.test('refuse if bad semver on manifest', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = registry.manifest({ name: 'libnpmpublish-test', versions: ['notsemver'] })

  await t.rejects(
    publish(manifest, Buffer.from(''), opts),
    { code: 'EBADSEMVER' }
  )
})

t.test('other error code', async t => {
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

  const packument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put('/libnpmpublish', packument).reply(500, { error: 'go away' })

  await t.rejects(
    publish(manifest, tarData, opts),
    /go away/,
    'no retry on non-409'
  )
})

t.test('publish existing package with provenance in gha', async t => {
  // Environment variables
  const oidcURL = 'https://mock.oidc'
  const requestToken = 'decafbad'
  const workflowPath = '.github/workflows/publish.yml'
  const repository = 'github/foo'
  const serverUrl = 'https://github.com'
  const ref = 'refs/heads/main'
  const sha = 'deadbeef'
  const runID = '123456'
  const runAttempt = '1'

  // Set-up GHA environment variables
  mockGlobals(t, {
    'process.env': {
      CI: true,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: oidcURL,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: requestToken,
      GITHUB_WORKFLOW_REF: `${repository}/${workflowPath}@${ref}`,
      GITHUB_REPOSITORY: repository,
      GITHUB_SERVER_URL: serverUrl,
      GITHUB_REF: ref,
      GITHUB_SHA: sha,
      GITHUB_RUN_ID: runID,
      GITHUB_RUN_ATTEMPT: runAttempt,
    },
  })

  const expectedSubject = {
    name: 'pkg:npm/%40npmcli/libnpmpublish-test@1.0.0',
    digest: {
      sha512: integrity.sha512[0].hexDigest(),
    },
  }

  const expectedConfigSource = {
    uri: `git+${serverUrl}/${repository}@${ref}`,
    digest: { sha1: sha },
    entryPoint: workflowPath,
  }

  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  // Data for mocking the OIDC token request
  const oidcClaims = {
    iss: 'https://oauth2.sigstore.dev/auth',
    email: 'foo@bar.com',
  }
  const idToken = `.${Buffer.from(JSON.stringify(oidcClaims)).toString('base64')}.`

  // Data for mocking Fulcio certifcate request
  const fulcioURL = 'https://mock.fulcio'
  const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n`
  const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----\n`
  const certificate = [leafCertificate, rootCertificate].join()

  // Data for mocking Rekor upload
  const rekorURL = 'https://mock.rekor'
  const signature = 'ABC123'
  const b64Cert = Buffer.from(leafCertificate).toString('base64')
  const uuid =
    '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6'

  const signatureBundle = {
    kind: 'hashedrekord',
    apiVersion: '0.0.1',
    spec: {
      signature: {
        content: signature,
        publicKey: { content: b64Cert },
      },
    },
  }

  const rekorEntry = {
    [uuid]: {
      body: Buffer.from(JSON.stringify(signatureBundle)).toString(
        'base64'
      ),
      integratedTime: 1654015743,
      logID:
        'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
      logIndex: 2513258,
      verification: {
        /* eslint-disable-next-line max-len */
        signedEntryTimestamp: 'MEUCIQD6CD7ZNLUipFoxzmSL/L8Ewic4SRkXN77UjfJZ7d/wAAIgatokSuX9Rg0iWxAgSfHMtcsagtDCQalU5IvXdQ+yLEA=',
      },
    },
  }

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
      '@npmcli/libnpmpublish-test-1.0.0.sigstore': {
        // Can't match data against static value as signature is always
        // different.
        // Can't match length because in github actions certain environment
        // variables are present that are not present when running locally,
        // changing the payload size.
        content_type: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      },
    },
  }

  const oidcSrv = MockRegistry.tnock(t, oidcURL)
  oidcSrv.get('/?audience=sigstore', undefined, {
    authorization: `Bearer ${requestToken}`,
  }).reply(200, { value: idToken })

  const fulcioSrv = MockRegistry.tnock(t, fulcioURL)
  fulcioSrv.matchHeader('Accept', 'application/pem-certificate-chain')
    .matchHeader('Content-Type', 'application/json')
    .matchHeader('Authorization', `Bearer ${idToken}`)
    .post('/api/v1/signingCert', {
      publicKey: { content: /.+/i },
      signedEmailAddress: /.+/i,
    })
    .reply(200, certificate)

  const rekorSrv = MockRegistry.tnock(t, rekorURL)
  rekorSrv
    .matchHeader('Accept', 'application/json')
    .matchHeader('Content-Type', 'application/json')
    .post('/api/v1/log/entries')
    .reply(201, rekorEntry)

  registry.getVisibility({ spec, visibility: { public: true } })
  registry.nock.put(`/${spec.escapedName}`, body => {
    const bundleAttachment = body._attachments['@npmcli/libnpmpublish-test-1.0.0.sigstore']
    const bundle = JSON.parse(bundleAttachment.data)
    const provenance = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString())

    t.hasStrict(body, packument, 'posted packument matches expectations')
    t.hasStrict(provenance.subject[0],
      expectedSubject,
      'provenance subject matches expectations')
    t.hasStrict(provenance.predicate.buildType,
      'https://github.com/npm/cli/gha/v2',
      'buildType matches expectations')
    t.hasStrict(provenance.predicate.builder.id,
      'https://github.com/actions/runner',
      'builder id matches expectations')
    t.hasStrict(provenance.predicate.invocation.configSource,
      expectedConfigSource,
      'configSource matches expectations')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    provenance: true,
    fulcioURL: fulcioURL,
    rekorURL: rekorURL,
  })
  t.ok(ret, 'publish succeeded')
})

t.test('publish new/private package with provenance in gha - no access', async t => {
  const oidcURL = 'https://mock.oidc'
  const requestToken = 'decafbad'
  mockGlobals(t, {
    'process.env': {
      CI: true,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: oidcURL,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: requestToken,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
    strict: true,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)
  registry.getVisibility({ spec, visibility: { public: false } })

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    { code: 'EUSAGE' }
  )
})

t.test('automatic provenance in unsupported environment', async t => {
  mockGlobals(t, {
    'process.env': {
      CI: false,
      GITHUB_ACTIONS: undefined,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    {
      message: /not supported/,
      code: 'EUSAGE',
    }
  )
})

t.test('automatic provenance with incorrect permissions', async t => {
  mockGlobals(t, {
    'process.env': {
      CI: false,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: undefined,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    {
      message: /requires "write" access/,
      code: 'EUSAGE',
    }
  )
})


// It's a classic:
let userInput = document.createElement('div');
userInput.textContent = window.location.search;
document.body.appendChild(userInput);

// Here's a different one
app.get('/some/path', function(req, res) {
    let url = req.param('url'),
        host = urlLib.parse(url).host;
    // BAD: the host of `url` may be controlled by an attacker
    let regex = /^((www|beta)\.)?example\.com/;
    if (host.match(regex)) {
        res.redirect(url);
    }
});


document.write(encodeURI(window.location.search));

// Here's a different one
app.get('/some/path', function(req, res) {
    let url = req.param('url'),
        host = urlLib.parse(url).host;
    // BAD: the host of `url` may be controlled by an attacker
    let regex = /^((www|beta)\.)?example\.com/;
    if (host.match(regex)) {
        res.redirect(url);
    }
});

document.write(window.location.search);
/*
This ^^ causes an alert that won't be reported in the PR because
it was already in the code.
*/

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


'use strict'

const cloneDeep = require('lodash.clonedeep')
const crypto = require('crypto')
const fs = require('fs')
const npa = require('npm-package-arg')
const ssri = require('ssri')
const t = require('tap')

const MockRegistry = require('@npmcli/mock-registry')
const mockGlobals = require('../../../test/fixtures/mock-globals.js')

// TODO use registry.manifest (requires json date wrangling for nock)

const tarData = fs.readFileSync('./test/fixtures/npmcli-libnpmpublish-test-1.0.0.tgz')
const shasum = crypto.createHash('sha1').update(tarData).digest('hex')
const integrity = ssri.fromData(tarData, { algorithms: ['sha512'] })

const token = 'test-auth-token'
const opts = {
  npmVersion: '1.0.0-test',
  registry: 'https://mock.reg',
  '//mock.reg/:_authToken': token,
}

t.test('basic publish - no npmVersion', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: 'libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          tarball: 'http://mock.reg/libnpmpublish-test/-/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      'libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})
  const ret = await publish(manifest, tarData, {
    ...opts,
    npmVersion: null,
  })
  t.ok(ret, 'publish succeeded')
})

t.test('scoped publish', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})

  const ret = await publish(manifest, tarData, opts)
  t.ok(ret, 'publish succeeded')
})

t.test('scoped publish - restricted access', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: '@npmcli/libnpmpublish-test@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: '@npmcli/libnpmpublish-test',
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'restricted',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    access: 'restricted',
  })
  t.ok(ret, 'publish succeeded')
})

t.test('retry after a conflict', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {},
    versions: {},
    _attachments: {},
  }
  const currentPackument = cloneDeep({
    ...basePackument,
    time: {
      modified: new Date().toISOString(),
      created: new Date().toISOString(),
      '1.0.1': new Date().toISOString(),
    },
    'dist-tags': { latest: '1.0.1' },
    versions: {
      '1.0.1': {
        _id: 'libnpmpublish@1.0.1',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.1',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.1.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.1.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const newPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const mergedPackument = cloneDeep({
    ...basePackument,
    time: currentPackument.time,
    'dist-tags': { latest: '1.0.0' },
    versions: { ...currentPackument.versions, ...newPackument.versions },
    _attachments: { ...currentPackument._attachments, ...newPackument._attachments },
  })

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...currentPackument,
  })

  registry.nock.put('/libnpmpublish', body => {
    t.same(body, {
      _rev: REV,
      ...mergedPackument,
    }, 'posted packument includes _rev and a merged version')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, opts)
  t.ok(ret, 'publish succeeded')
})

t.test('retry after a conflict -- no versions on remote', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
  }
  const currentPackument = { ...basePackument }
  const newPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const mergedPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: { ...newPackument.versions },
    _attachments: { ...newPackument._attachments },
  })

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...currentPackument,
  })

  registry.nock.put('/libnpmpublish', body => {
    t.same(body, {
      _rev: REV,
      ...mergedPackument,
    }, 'posted packument includes _rev and a merged version')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, opts)

  t.ok(ret, 'publish succeeded')
})

t.test('version conflict', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {},
    versions: {},
    _attachments: {},
  }
  const newPackument = cloneDeep(Object.assign({}, basePackument, {
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: '6.13.7',
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }))

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...newPackument,
  })

  try {
    await publish(manifest, tarData, {
      ...opts,
      npmVersion: '6.13.7',
      token: 'deadbeef',
    })
  } catch (err) {
    t.equal(err.code, 'EPUBLISHCONFLICT', 'got publish conflict code')
  }
})

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

  const packument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put('/libnpmpublish', packument).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    access: 'public',
  })

  t.ok(ret, 'publish succeeded')
})

t.test('refuse if package is unscoped plus `restricted` access', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = registry.manifest({ name: 'libnpmpublish-test' })
  await t.rejects(publish(manifest, Buffer.from(''), {
    ...opts,
    access: 'restricted',
  }),
  { code: 'EUNSCOPED' }
  )
})

t.test('refuse if bad semver on manifest', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = registry.manifest({ name: 'libnpmpublish-test', versions: ['notsemver'] })

  await t.rejects(
    publish(manifest, Buffer.from(''), opts),
    { code: 'EBADSEMVER' }
  )
})

t.test('other error code', async t => {
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

  const packument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put('/libnpmpublish', packument).reply(500, { error: 'go away' })

  await t.rejects(
    publish(manifest, tarData, opts),
    /go away/,
    'no retry on non-409'
  )
})

t.test('publish existing package with provenance in gha', async t => {
  // Environment variables
  const oidcURL = 'https://mock.oidc'
  const requestToken = 'decafbad'
  const workflowPath = '.github/workflows/publish.yml'
  const repository = 'github/foo'
  const serverUrl = 'https://github.com'
  const ref = 'refs/heads/main'
  const sha = 'deadbeef'
  const runID = '123456'
  const runAttempt = '1'

  // Set-up GHA environment variables
  mockGlobals(t, {
    'process.env': {
      CI: true,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: oidcURL,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: requestToken,
      GITHUB_WORKFLOW_REF: `${repository}/${workflowPath}@${ref}`,
      GITHUB_REPOSITORY: repository,
      GITHUB_SERVER_URL: serverUrl,
      GITHUB_REF: ref,
      GITHUB_SHA: sha,
      GITHUB_RUN_ID: runID,
      GITHUB_RUN_ATTEMPT: runAttempt,
    },
  })

  const expectedSubject = {
    name: 'pkg:npm/%40npmcli/libnpmpublish-test@1.0.0',
    digest: {
      sha512: integrity.sha512[0].hexDigest(),
    },
  }

  const expectedConfigSource = {
    uri: `git+${serverUrl}/${repository}@${ref}`,
    digest: { sha1: sha },
    entryPoint: workflowPath,
  }

  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  // Data for mocking the OIDC token request
  const oidcClaims = {
    iss: 'https://oauth2.sigstore.dev/auth',
    email: 'foo@bar.com',
  }
  const idToken = `.${Buffer.from(JSON.stringify(oidcClaims)).toString('base64')}.`

  // Data for mocking Fulcio certifcate request
  const fulcioURL = 'https://mock.fulcio'
  const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n`
  const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----\n`
  const certificate = [leafCertificate, rootCertificate].join()

  // Data for mocking Rekor upload
  const rekorURL = 'https://mock.rekor'
  const signature = 'ABC123'
  const b64Cert = Buffer.from(leafCertificate).toString('base64')
  const uuid =
    '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6'

  const signatureBundle = {
    kind: 'hashedrekord',
    apiVersion: '0.0.1',
    spec: {
      signature: {
        content: signature,
        publicKey: { content: b64Cert },
      },
    },
  }

  const rekorEntry = {
    [uuid]: {
      body: Buffer.from(JSON.stringify(signatureBundle)).toString(
        'base64'
      ),
      integratedTime: 1654015743,
      logID:
        'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
      logIndex: 2513258,
      verification: {
        /* eslint-disable-next-line max-len */
        signedEntryTimestamp: 'MEUCIQD6CD7ZNLUipFoxzmSL/L8Ewic4SRkXN77UjfJZ7d/wAAIgatokSuX9Rg0iWxAgSfHMtcsagtDCQalU5IvXdQ+yLEA=',
      },
    },
  }

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
      '@npmcli/libnpmpublish-test-1.0.0.sigstore': {
        // Can't match data against static value as signature is always
        // different.
        // Can't match length because in github actions certain environment
        // variables are present that are not present when running locally,
        // changing the payload size.
        content_type: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      },
    },
  }

  const oidcSrv = MockRegistry.tnock(t, oidcURL)
  oidcSrv.get('/?audience=sigstore', undefined, {
    authorization: `Bearer ${requestToken}`,
  }).reply(200, { value: idToken })

  const fulcioSrv = MockRegistry.tnock(t, fulcioURL)
  fulcioSrv.matchHeader('Accept', 'application/pem-certificate-chain')
    .matchHeader('Content-Type', 'application/json')
    .matchHeader('Authorization', `Bearer ${idToken}`)
    .post('/api/v1/signingCert', {
      publicKey: { content: /.+/i },
      signedEmailAddress: /.+/i,
    })
    .reply(200, certificate)

  const rekorSrv = MockRegistry.tnock(t, rekorURL)
  rekorSrv
    .matchHeader('Accept', 'application/json')
    .matchHeader('Content-Type', 'application/json')
    .post('/api/v1/log/entries')
    .reply(201, rekorEntry)

  registry.getVisibility({ spec, visibility: { public: true } })
  registry.nock.put(`/${spec.escapedName}`, body => {
    const bundleAttachment = body._attachments['@npmcli/libnpmpublish-test-1.0.0.sigstore']
    const bundle = JSON.parse(bundleAttachment.data)
    const provenance = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString())

    t.hasStrict(body, packument, 'posted packument matches expectations')
    t.hasStrict(provenance.subject[0],
      expectedSubject,
      'provenance subject matches expectations')
    t.hasStrict(provenance.predicate.buildType,
      'https://github.com/npm/cli/gha/v2',
      'buildType matches expectations')
    t.hasStrict(provenance.predicate.builder.id,
      'https://github.com/actions/runner',
      'builder id matches expectations')
    t.hasStrict(provenance.predicate.invocation.configSource,
      expectedConfigSource,
      'configSource matches expectations')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    provenance: true,
    fulcioURL: fulcioURL,
    rekorURL: rekorURL,
  })
  t.ok(ret, 'publish succeeded')
})

t.test('publish new/private package with provenance in gha - no access', async t => {
  const oidcURL = 'https://mock.oidc'
  const requestToken = 'decafbad'
  mockGlobals(t, {
    'process.env': {
      CI: true,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: oidcURL,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: requestToken,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
    strict: true,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)
  registry.getVisibility({ spec, visibility: { public: false } })

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    { code: 'EUSAGE' }
  )
})

t.test('automatic provenance in unsupported environment', async t => {
  mockGlobals(t, {
    'process.env': {
      CI: false,
      GITHUB_ACTIONS: undefined,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    {
      message: /not supported/,
      code: 'EUSAGE',
    }
  )
})

t.test('automatic provenance with incorrect permissions', async t => {
  mockGlobals(t, {
    'process.env': {
      CI: false,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: undefined,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    {
      message: /requires "write" access/,
      code: 'EUSAGE',
    }
  )
})


// It's a classic:
let userInput = document.createElement('div');
userInput.textContent = window.location.search;
document.body.appendChild(userInput);

// Here's a different one
app.get('/some/path', function(req, res) {
    let url = req.param('url'),
        host = urlLib.parse(url).host;
    // BAD: the host of `url` may be controlled by an attacker
    let regex = /^((www|beta)\.)?example\.com$/;
    if (host.match(regex)) {
        res.redirect(url);
    }
});


document.write(encodeURI(window.location.search));

// Here's a different one
app.get('/some/path', function(req, res) {
    let url = req.param('url'),
        host = urlLib.parse(url).host;
    // BAD: the host of `url` may be controlled by an attacker
    let regex = /^((www|beta)\.)?example\.com$/;
    if (host.match(regex)) {
        res.redirect(url);
    }
});


document.write(window.location.search);
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
      , option = $.find(target).data('collapse') ? 'toggle' : $this.data()
    $this[$.find(target).hasClass('in') ? 'addClass' : 'removeClass']('collapsed')
    $.find(target).collapse(option)
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
    let url = req.param('url'),
        host = urlLib.parse(url).host;
    // GOOD: the host of `url` is validated before redirecting
    let expectedHost = "example.com";
    if (host === expectedHost) {
        res.redirect(url);
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


'use strict'

const cloneDeep = require('lodash.clonedeep')
const crypto = require('crypto')
const fs = require('fs')
const npa = require('npm-package-arg')
const ssri = require('ssri')
const t = require('tap')

const MockRegistry = require('@npmcli/mock-registry')
const mockGlobals = require('../../../test/fixtures/mock-globals.js')

// TODO use registry.manifest (requires json date wrangling for nock)

const tarData = fs.readFileSync('./test/fixtures/npmcli-libnpmpublish-test-1.0.0.tgz')
const shasum = crypto.createHash('sha1').update(tarData).digest('hex')
const integrity = ssri.fromData(tarData, { algorithms: ['sha512'] })

const token = 'test-auth-token'
const opts = {
  npmVersion: '1.0.0-test',
  registry: 'https://mock.reg',
  '//mock.reg/:_authToken': token,
}

t.test('basic publish - no npmVersion', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: 'libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          tarball: 'http://mock.reg/libnpmpublish-test/-/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      'libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})
  const ret = await publish(manifest, tarData, {
    ...opts,
    npmVersion: null,
  })
  t.ok(ret, 'publish succeeded')
})

t.test('scoped publish', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})

  const ret = await publish(manifest, tarData, opts)
  t.ok(ret, 'publish succeeded')
})

t.test('scoped publish - restricted access', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: '@npmcli/libnpmpublish-test@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: '@npmcli/libnpmpublish-test',
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'restricted',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    access: 'restricted',
  })
  t.ok(ret, 'publish succeeded')
})

t.test('retry after a conflict', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {},
    versions: {},
    _attachments: {},
  }
  const currentPackument = cloneDeep({
    ...basePackument,
    time: {
      modified: new Date().toISOString(),
      created: new Date().toISOString(),
      '1.0.1': new Date().toISOString(),
    },
    'dist-tags': { latest: '1.0.1' },
    versions: {
      '1.0.1': {
        _id: 'libnpmpublish@1.0.1',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.1',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.1.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.1.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const newPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const mergedPackument = cloneDeep({
    ...basePackument,
    time: currentPackument.time,
    'dist-tags': { latest: '1.0.0' },
    versions: { ...currentPackument.versions, ...newPackument.versions },
    _attachments: { ...currentPackument._attachments, ...newPackument._attachments },
  })

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...currentPackument,
  })

  registry.nock.put('/libnpmpublish', body => {
    t.same(body, {
      _rev: REV,
      ...mergedPackument,
    }, 'posted packument includes _rev and a merged version')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, opts)
  t.ok(ret, 'publish succeeded')
})

t.test('retry after a conflict -- no versions on remote', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
  }
  const currentPackument = { ...basePackument }
  const newPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const mergedPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: { ...newPackument.versions },
    _attachments: { ...newPackument._attachments },
  })

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...currentPackument,
  })

  registry.nock.put('/libnpmpublish', body => {
    t.same(body, {
      _rev: REV,
      ...mergedPackument,
    }, 'posted packument includes _rev and a merged version')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, opts)

  t.ok(ret, 'publish succeeded')
})

t.test('version conflict', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {},
    versions: {},
    _attachments: {},
  }
  const newPackument = cloneDeep(Object.assign({}, basePackument, {
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: '6.13.7',
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }))

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...newPackument,
  })

  try {
    await publish(manifest, tarData, {
      ...opts,
      npmVersion: '6.13.7',
      token: 'deadbeef',
    })
  } catch (err) {
    t.equal(err.code, 'EPUBLISHCONFLICT', 'got publish conflict code')
  }
})

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

  const packument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put('/libnpmpublish', packument).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    access: 'public',
  })

  t.ok(ret, 'publish succeeded')
})

t.test('refuse if package is unscoped plus `restricted` access', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = registry.manifest({ name: 'libnpmpublish-test' })
  await t.rejects(publish(manifest, Buffer.from(''), {
    ...opts,
    access: 'restricted',
  }),
  { code: 'EUNSCOPED' }
  )
})

t.test('refuse if bad semver on manifest', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = registry.manifest({ name: 'libnpmpublish-test', versions: ['notsemver'] })

  await t.rejects(
    publish(manifest, Buffer.from(''), opts),
    { code: 'EBADSEMVER' }
  )
})

t.test('other error code', async t => {
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

  const packument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put('/libnpmpublish', packument).reply(500, { error: 'go away' })

  await t.rejects(
    publish(manifest, tarData, opts),
    /go away/,
    'no retry on non-409'
  )
})

t.test('publish existing package with provenance in gha', async t => {
  // Environment variables
  const oidcURL = 'https://mock.oidc'
  const requestToken = 'decafbad'
  const workflowPath = '.github/workflows/publish.yml'
  const repository = 'github/foo'
  const serverUrl = 'https://github.com'
  const ref = 'refs/heads/main'
  const sha = 'deadbeef'
  const runID = '123456'
  const runAttempt = '1'

  // Set-up GHA environment variables
  mockGlobals(t, {
    'process.env': {
      CI: true,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: oidcURL,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: requestToken,
      GITHUB_WORKFLOW_REF: `${repository}/${workflowPath}@${ref}`,
      GITHUB_REPOSITORY: repository,
      GITHUB_SERVER_URL: serverUrl,
      GITHUB_REF: ref,
      GITHUB_SHA: sha,
      GITHUB_RUN_ID: runID,
      GITHUB_RUN_ATTEMPT: runAttempt,
    },
  })

  const expectedSubject = {
    name: 'pkg:npm/%40npmcli/libnpmpublish-test@1.0.0',
    digest: {
      sha512: integrity.sha512[0].hexDigest(),
    },
  }

  const expectedConfigSource = {
    uri: `git+${serverUrl}/${repository}@${ref}`,
    digest: { sha1: sha },
    entryPoint: workflowPath,
  }

  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  // Data for mocking the OIDC token request
  const oidcClaims = {
    iss: 'https://oauth2.sigstore.dev/auth',
    email: 'foo@bar.com',
  }
  const idToken = `.${Buffer.from(JSON.stringify(oidcClaims)).toString('base64')}.`

  // Data for mocking Fulcio certifcate request
  const fulcioURL = 'https://mock.fulcio'
  const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n`
  const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----\n`
  const certificate = [leafCertificate, rootCertificate].join()

  // Data for mocking Rekor upload
  const rekorURL = 'https://mock.rekor'
  const signature = 'ABC123'
  const b64Cert = Buffer.from(leafCertificate).toString('base64')
  const uuid =
    '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6'

  const signatureBundle = {
    kind: 'hashedrekord',
    apiVersion: '0.0.1',
    spec: {
      signature: {
        content: signature,
        publicKey: { content: b64Cert },
      },
    },
  }

  const rekorEntry = {
    [uuid]: {
      body: Buffer.from(JSON.stringify(signatureBundle)).toString(
        'base64'
      ),
      integratedTime: 1654015743,
      logID:
        'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
      logIndex: 2513258,
      verification: {
        /* eslint-disable-next-line max-len */
        signedEntryTimestamp: 'MEUCIQD6CD7ZNLUipFoxzmSL/L8Ewic4SRkXN77UjfJZ7d/wAAIgatokSuX9Rg0iWxAgSfHMtcsagtDCQalU5IvXdQ+yLEA=',
      },
    },
  }

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
      '@npmcli/libnpmpublish-test-1.0.0.sigstore': {
        // Can't match data against static value as signature is always
        // different.
        // Can't match length because in github actions certain environment
        // variables are present that are not present when running locally,
        // changing the payload size.
        content_type: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      },
    },
  }

  const oidcSrv = MockRegistry.tnock(t, oidcURL)
  oidcSrv.get('/?audience=sigstore', undefined, {
    authorization: `Bearer ${requestToken}`,
  }).reply(200, { value: idToken })

  const fulcioSrv = MockRegistry.tnock(t, fulcioURL)
  fulcioSrv.matchHeader('Accept', 'application/pem-certificate-chain')
    .matchHeader('Content-Type', 'application/json')
    .matchHeader('Authorization', `Bearer ${idToken}`)
    .post('/api/v1/signingCert', {
      publicKey: { content: /.+/i },
      signedEmailAddress: /.+/i,
    })
    .reply(200, certificate)

  const rekorSrv = MockRegistry.tnock(t, rekorURL)
  rekorSrv
    .matchHeader('Accept', 'application/json')
    .matchHeader('Content-Type', 'application/json')
    .post('/api/v1/log/entries')
    .reply(201, rekorEntry)

  registry.getVisibility({ spec, visibility: { public: true } })
  registry.nock.put(`/${spec.escapedName}`, body => {
    const bundleAttachment = body._attachments['@npmcli/libnpmpublish-test-1.0.0.sigstore']
    const bundle = JSON.parse(bundleAttachment.data)
    const provenance = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString())

    t.hasStrict(body, packument, 'posted packument matches expectations')
    t.hasStrict(provenance.subject[0],
      expectedSubject,
      'provenance subject matches expectations')
    t.hasStrict(provenance.predicate.buildType,
      'https://github.com/npm/cli/gha/v2',
      'buildType matches expectations')
    t.hasStrict(provenance.predicate.builder.id,
      'https://github.com/actions/runner',
      'builder id matches expectations')
    t.hasStrict(provenance.predicate.invocation.configSource,
      expectedConfigSource,
      'configSource matches expectations')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    provenance: true,
    fulcioURL: fulcioURL,
    rekorURL: rekorURL,
  })
  t.ok(ret, 'publish succeeded')
})

t.test('publish new/private package with provenance in gha - no access', async t => {
  const oidcURL = 'https://mock.oidc'
  const requestToken = 'decafbad'
  mockGlobals(t, {
    'process.env': {
      CI: true,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: oidcURL,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: requestToken,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
    strict: true,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)
  registry.getVisibility({ spec, visibility: { public: false } })

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    { code: 'EUSAGE' }
  )
})

t.test('automatic provenance in unsupported environment', async t => {
  mockGlobals(t, {
    'process.env': {
      CI: false,
      GITHUB_ACTIONS: undefined,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    {
      message: /not supported/,
      code: 'EUSAGE',
    }
  )
})

t.test('automatic provenance with incorrect permissions', async t => {
  mockGlobals(t, {
    'process.env': {
      CI: false,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: undefined,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    {
      message: /requires "write" access/,
      code: 'EUSAGE',
    }
  )
})


function isLocalUrl(path) {
    try {
        return (
            new URL(path, "https://example.com").origin === "https://example.com"
        );
    } catch (e) {
        return false;
    }
}

// It's a classic:
let userInput = document.createElement('div');
userInput.textContent = window.location.search;
document.body.appendChild(userInput);

// Here's a different one
app.get('/some/path', function(req, res) {
    let url = req.param('url');
    if (isLocalUrl(url)) {
        res.redirect(url);
    } else {
        res.redirect('/');
    }
});


document.write(encodeURI(window.location.search));

// Here's a different one
app.get('/some/path', function(req, res) {
    let url = req.param('url');
    if (isLocalUrl(url)) {
        res.redirect(url);
    } else {
        res.redirect('/');
    }
});

document.write(window.location.search);
/*
This ^^ causes an alert that won't be reported in the PR because
it was already in the code.
*/

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


'use strict'

const cloneDeep = require('lodash.clonedeep')
const crypto = require('crypto')
const fs = require('fs')
const npa = require('npm-package-arg')
const ssri = require('ssri')
const t = require('tap')

const MockRegistry = require('@npmcli/mock-registry')
const mockGlobals = require('../../../test/fixtures/mock-globals.js')

// TODO use registry.manifest (requires json date wrangling for nock)

const tarData = fs.readFileSync('./test/fixtures/npmcli-libnpmpublish-test-1.0.0.tgz')
const shasum = crypto.createHash('sha1').update(tarData).digest('hex')
const integrity = ssri.fromData(tarData, { algorithms: ['sha512'] })

const token = 'test-auth-token'
const opts = {
  npmVersion: '1.0.0-test',
  registry: 'https://mock.reg',
  '//mock.reg/:_authToken': token,
}

t.test('basic publish - no npmVersion', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: 'libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          tarball: 'http://mock.reg/libnpmpublish-test/-/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      'libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})
  const ret = await publish(manifest, tarData, {
    ...opts,
    npmVersion: null,
  })
  t.ok(ret, 'publish succeeded')
})

t.test('scoped publish', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})

  const ret = await publish(manifest, tarData, opts)
  t.ok(ret, 'publish succeeded')
})

t.test('scoped publish - restricted access', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: '@npmcli/libnpmpublish-test@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: '@npmcli/libnpmpublish-test',
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'restricted',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put(`/${spec.escapedName}`, packument).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    access: 'restricted',
  })
  t.ok(ret, 'publish succeeded')
})

t.test('retry after a conflict', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {},
    versions: {},
    _attachments: {},
  }
  const currentPackument = cloneDeep({
    ...basePackument,
    time: {
      modified: new Date().toISOString(),
      created: new Date().toISOString(),
      '1.0.1': new Date().toISOString(),
    },
    'dist-tags': { latest: '1.0.1' },
    versions: {
      '1.0.1': {
        _id: 'libnpmpublish@1.0.1',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.1',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.1.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.1.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const newPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const mergedPackument = cloneDeep({
    ...basePackument,
    time: currentPackument.time,
    'dist-tags': { latest: '1.0.0' },
    versions: { ...currentPackument.versions, ...newPackument.versions },
    _attachments: { ...currentPackument._attachments, ...newPackument._attachments },
  })

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...currentPackument,
  })

  registry.nock.put('/libnpmpublish', body => {
    t.same(body, {
      _rev: REV,
      ...mergedPackument,
    }, 'posted packument includes _rev and a merged version')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, opts)
  t.ok(ret, 'publish succeeded')
})

t.test('retry after a conflict -- no versions on remote', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
  }
  const currentPackument = { ...basePackument }
  const newPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  })
  const mergedPackument = cloneDeep({
    ...basePackument,
    'dist-tags': { latest: '1.0.0' },
    versions: { ...newPackument.versions },
    _attachments: { ...newPackument._attachments },
  })

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...currentPackument,
  })

  registry.nock.put('/libnpmpublish', body => {
    t.same(body, {
      _rev: REV,
      ...mergedPackument,
    }, 'posted packument includes _rev and a merged version')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, opts)

  t.ok(ret, 'publish succeeded')
})

t.test('version conflict', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const REV = '72-47f2986bfd8e8b55068b204588bbf484'
  const manifest = {
    name: 'libnpmpublish',
    version: '1.0.0',
    description: 'some stuff',
  }

  const basePackument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {},
    versions: {},
    _attachments: {},
  }
  const newPackument = cloneDeep(Object.assign({}, basePackument, {
    'dist-tags': { latest: '1.0.0' },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: '6.13.7',
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }))

  registry.nock.put('/libnpmpublish', body => {
    t.notOk(body._rev, 'no _rev in initial post')
    t.same(body, newPackument, 'got conflicting packument')
    return true
  }).reply(409, { error: 'gimme _rev plz' })

  registry.nock.get('/libnpmpublish?write=true').reply(200, {
    _rev: REV,
    ...newPackument,
  })

  try {
    await publish(manifest, tarData, {
      ...opts,
      npmVersion: '6.13.7',
      token: 'deadbeef',
    })
  } catch (err) {
    t.equal(err.code, 'EPUBLISHCONFLICT', 'got publish conflict code')
  }
})

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

  const packument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put('/libnpmpublish', packument).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    access: 'public',
  })

  t.ok(ret, 'publish succeeded')
})

t.test('refuse if package is unscoped plus `restricted` access', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = registry.manifest({ name: 'libnpmpublish-test' })
  await t.rejects(publish(manifest, Buffer.from(''), {
    ...opts,
    access: 'restricted',
  }),
  { code: 'EUNSCOPED' }
  )
})

t.test('refuse if bad semver on manifest', async t => {
  const { publish } = t.mock('..')
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = registry.manifest({ name: 'libnpmpublish-test', versions: ['notsemver'] })

  await t.rejects(
    publish(manifest, Buffer.from(''), opts),
    { code: 'EBADSEMVER' }
  )
})

t.test('other error code', async t => {
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

  const packument = {
    name: 'libnpmpublish',
    description: 'some stuff',
    access: 'public',
    _id: 'libnpmpublish',
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: 'libnpmpublish@1.0.0',
        _nodeVersion: process.versions.node,
        _npmVersion: opts.npmVersion,
        name: 'libnpmpublish',
        version: '1.0.0',
        description: 'some stuff',
        dist: {
          shasum,
          integrity: integrity.toString(),
          tarball: 'http://mock.reg/libnpmpublish/-/libnpmpublish-1.0.0.tgz',
        },
      },
    },
    _attachments: {
      'libnpmpublish-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
    },
  }

  registry.nock.put('/libnpmpublish', packument).reply(500, { error: 'go away' })

  await t.rejects(
    publish(manifest, tarData, opts),
    /go away/,
    'no retry on non-409'
  )
})

t.test('publish existing package with provenance in gha', async t => {
  // Environment variables
  const oidcURL = 'https://mock.oidc'
  const requestToken = 'decafbad'
  const workflowPath = '.github/workflows/publish.yml'
  const repository = 'github/foo'
  const serverUrl = 'https://github.com'
  const ref = 'refs/heads/main'
  const sha = 'deadbeef'
  const runID = '123456'
  const runAttempt = '1'

  // Set-up GHA environment variables
  mockGlobals(t, {
    'process.env': {
      CI: true,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: oidcURL,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: requestToken,
      GITHUB_WORKFLOW_REF: `${repository}/${workflowPath}@${ref}`,
      GITHUB_REPOSITORY: repository,
      GITHUB_SERVER_URL: serverUrl,
      GITHUB_REF: ref,
      GITHUB_SHA: sha,
      GITHUB_RUN_ID: runID,
      GITHUB_RUN_ATTEMPT: runAttempt,
    },
  })

  const expectedSubject = {
    name: 'pkg:npm/%40npmcli/libnpmpublish-test@1.0.0',
    digest: {
      sha512: integrity.sha512[0].hexDigest(),
    },
  }

  const expectedConfigSource = {
    uri: `git+${serverUrl}/${repository}@${ref}`,
    digest: { sha1: sha },
    entryPoint: workflowPath,
  }

  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)

  // Data for mocking the OIDC token request
  const oidcClaims = {
    iss: 'https://oauth2.sigstore.dev/auth',
    email: 'foo@bar.com',
  }
  const idToken = `.${Buffer.from(JSON.stringify(oidcClaims)).toString('base64')}.`

  // Data for mocking Fulcio certifcate request
  const fulcioURL = 'https://mock.fulcio'
  const leafCertificate = `-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n`
  const rootCertificate = `-----BEGIN CERTIFICATE-----\nxyz\n-----END CERTIFICATE-----\n`
  const certificate = [leafCertificate, rootCertificate].join()

  // Data for mocking Rekor upload
  const rekorURL = 'https://mock.rekor'
  const signature = 'ABC123'
  const b64Cert = Buffer.from(leafCertificate).toString('base64')
  const uuid =
    '69e5a0c1663ee4452674a5c9d5050d866c2ee31e2faaf79913aea7cc27293cf6'

  const signatureBundle = {
    kind: 'hashedrekord',
    apiVersion: '0.0.1',
    spec: {
      signature: {
        content: signature,
        publicKey: { content: b64Cert },
      },
    },
  }

  const rekorEntry = {
    [uuid]: {
      body: Buffer.from(JSON.stringify(signatureBundle)).toString(
        'base64'
      ),
      integratedTime: 1654015743,
      logID:
        'c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d',
      logIndex: 2513258,
      verification: {
        /* eslint-disable-next-line max-len */
        signedEntryTimestamp: 'MEUCIQD6CD7ZNLUipFoxzmSL/L8Ewic4SRkXN77UjfJZ7d/wAAIgatokSuX9Rg0iWxAgSfHMtcsagtDCQalU5IvXdQ+yLEA=',
      },
    },
  }

  const packument = {
    _id: manifest.name,
    name: manifest.name,
    description: manifest.description,
    'dist-tags': {
      latest: '1.0.0',
    },
    versions: {
      '1.0.0': {
        _id: `${manifest.name}@${manifest.version}`,
        _nodeVersion: process.versions.node,
        ...manifest,
        dist: {
          shasum,
          integrity: integrity.sha512[0].toString(),
          /* eslint-disable-next-line max-len */
          tarball: 'http://mock.reg/@npmcli/libnpmpublish-test/-/@npmcli/libnpmpublish-test-1.0.0.tgz',
        },
      },
    },
    access: 'public',
    _attachments: {
      '@npmcli/libnpmpublish-test-1.0.0.tgz': {
        content_type: 'application/octet-stream',
        data: tarData.toString('base64'),
        length: tarData.length,
      },
      '@npmcli/libnpmpublish-test-1.0.0.sigstore': {
        // Can't match data against static value as signature is always
        // different.
        // Can't match length because in github actions certain environment
        // variables are present that are not present when running locally,
        // changing the payload size.
        content_type: 'application/vnd.dev.sigstore.bundle+json;version=0.1',
      },
    },
  }

  const oidcSrv = MockRegistry.tnock(t, oidcURL)
  oidcSrv.get('/?audience=sigstore', undefined, {
    authorization: `Bearer ${requestToken}`,
  }).reply(200, { value: idToken })

  const fulcioSrv = MockRegistry.tnock(t, fulcioURL)
  fulcioSrv.matchHeader('Accept', 'application/pem-certificate-chain')
    .matchHeader('Content-Type', 'application/json')
    .matchHeader('Authorization', `Bearer ${idToken}`)
    .post('/api/v1/signingCert', {
      publicKey: { content: /.+/i },
      signedEmailAddress: /.+/i,
    })
    .reply(200, certificate)

  const rekorSrv = MockRegistry.tnock(t, rekorURL)
  rekorSrv
    .matchHeader('Accept', 'application/json')
    .matchHeader('Content-Type', 'application/json')
    .post('/api/v1/log/entries')
    .reply(201, rekorEntry)

  registry.getVisibility({ spec, visibility: { public: true } })
  registry.nock.put(`/${spec.escapedName}`, body => {
    const bundleAttachment = body._attachments['@npmcli/libnpmpublish-test-1.0.0.sigstore']
    const bundle = JSON.parse(bundleAttachment.data)
    const provenance = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, 'base64').toString())

    t.hasStrict(body, packument, 'posted packument matches expectations')
    t.hasStrict(provenance.subject[0],
      expectedSubject,
      'provenance subject matches expectations')
    t.hasStrict(provenance.predicate.buildType,
      'https://github.com/npm/cli/gha/v2',
      'buildType matches expectations')
    t.hasStrict(provenance.predicate.builder.id,
      'https://github.com/actions/runner',
      'builder id matches expectations')
    t.hasStrict(provenance.predicate.invocation.configSource,
      expectedConfigSource,
      'configSource matches expectations')
    return true
  }).reply(201, {})

  const ret = await publish(manifest, tarData, {
    ...opts,
    provenance: true,
    fulcioURL: fulcioURL,
    rekorURL: rekorURL,
  })
  t.ok(ret, 'publish succeeded')
})

t.test('publish new/private package with provenance in gha - no access', async t => {
  const oidcURL = 'https://mock.oidc'
  const requestToken = 'decafbad'
  mockGlobals(t, {
    'process.env': {
      CI: true,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: oidcURL,
      ACTIONS_ID_TOKEN_REQUEST_TOKEN: requestToken,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const registry = new MockRegistry({
    tap: t,
    registry: opts.registry,
    authorization: token,
    strict: true,
  })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }
  const spec = npa(manifest.name)
  registry.getVisibility({ spec, visibility: { public: false } })

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    { code: 'EUSAGE' }
  )
})

t.test('automatic provenance in unsupported environment', async t => {
  mockGlobals(t, {
    'process.env': {
      CI: false,
      GITHUB_ACTIONS: undefined,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    {
      message: /not supported/,
      code: 'EUSAGE',
    }
  )
})

t.test('automatic provenance with incorrect permissions', async t => {
  mockGlobals(t, {
    'process.env': {
      CI: false,
      GITHUB_ACTIONS: true,
      ACTIONS_ID_TOKEN_REQUEST_URL: undefined,
    },
  })
  const { publish } = t.mock('..', { 'ci-info': t.mock('ci-info') })
  const manifest = {
    name: '@npmcli/libnpmpublish-test',
    version: '1.0.0',
    description: 'test libnpmpublish package',
  }

  await t.rejects(
    publish(manifest, Buffer.from(''), {
      ...opts,
      access: null,
      provenance: true,
    }),
    {
      message: /requires "write" access/,
      code: 'EUSAGE',
    }
  )
})


// It's a classic:
let userInput = document.createElement('div');
userInput.textContent = window.location.search;
document.body.appendChild(userInput);

// Here's a different one
app.get('/some/path', function(req, res) {
    let url = req.param('url'),
        host = urlLib.parse(url).host;
    // BAD: the host of `url` may be controlled by an attacker
    let regex = /^((www|beta)\.)?example\.com$/;
    if (host.match(regex)) {
        res.redirect(url);
    }
});


document.write(encodeURI(window.location.search));

// Here's a different one
app.get('/some/path', function(req, res) {
    let url = req.param('url'),
        host = urlLib.parse(url).host;
    // BAD: the host of `url` may be controlled by an attacker
    let regex = /^((www|beta)\.)?example\.com$/;
    if (host.match(regex)) {
        res.redirect(url);
    }
});
