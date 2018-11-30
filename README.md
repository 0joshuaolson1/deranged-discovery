Tested with a recent version of Chromium. Firefox doesn't have BigInts at the time of writing, but Safari preview release 59 does; I don't know if its repl supports top-level `await`.

1. Allow popups.
2. If using a mobile browser (tested with Android's Chrome), use the [awkward webpage version](https://0joshuaolson1.github.io/media-multiverse-mobile/) (ignore step 3 below except for the media types). Otherwise, install and enable (change a setting in Safari?) a CORS extension.
3. Copy code from
- https://raw.githubusercontent.com/0joshuaolson1/media-multiverse/master/s.js - SoundCloud
- https://raw.githubusercontent.com/0joshuaolson1/media-multiverse/master/b.js - BandCamp
- https://raw.githubusercontent.com/0joshuaolson1/media-multiverse/master/w.js - websites
- https://raw.githubusercontent.com/0joshuaolson1/media-multiverse/master/f.js - heh

and paste in a blank tab's developer/JavaScript console (about:blank).

## Note

I don't use a CORS extension for BandCamp (b.js takes a while) - it interferes with using some other websites at the same time. I run the code from [a page in the BandCamp domain](https://bandcamp.com/robots.txt).
