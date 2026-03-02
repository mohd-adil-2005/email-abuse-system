"""
Utility functions for email abuse detection.
"""
import re
import hashlib
import os
import requests
import math
from typing import List, Set, Tuple
import logging
import joblib
import numpy as np

logger = logging.getLogger(__name__)

# Salt for phone hashing (from environment)
SALT = os.getenv("SALT", "default_salt_change_in_production")

# Disposable email domains (fetched from GitHub)
DISPOSABLE_DOMAINS: Set[str] = set()

# Keywords that indicate spam
SPAM_KEYWORDS = [
    "spam", "test", "fake", "temp", "temporary", "throwaway",
    "trash", "noreply", "no-reply", "donotreply", "nobody",
    "example", "sample", "demo", "trial", "free", "promo"
]

# Regex patterns for suspicious emails
RANDOM_PATTERNS = [
    r'^[a-z0-9]{8,}@',  # Long random local part
    r'^[a-z]+[0-9]{4,}@',  # Letters followed by many digits
    r'^[0-9]{4,}[a-z]+@',  # Many digits followed by letters
    r'^[a-z0-9]{6,}[_-][a-z0-9]{6,}@',  # Random-seeming with separators
]


# Global model variable
SPAM_MODEL = None
MODEL_PATH = os.path.join(os.path.dirname(__file__), "spam_model.joblib")


def hash_phone(phone: str) -> str:
    """
    Hash phone number using SHA256 with salt.
    
    Args:
        phone: Phone number in E.164 format
        
    Returns:
        SHA256 hash as hex string
    """
    salted = phone + SALT
    return hashlib.sha256(salted.encode()).hexdigest()


def normalize_phone(phone: str) -> str:
    """
    Normalize phone number to E.164 format.
    
    Args:
        phone: Raw phone number string
        
    Returns:
        Normalized phone number (e.g., +1234567890)
    """
    # Remove all non-digit characters except +
    digits = ''.join(filter(str.isdigit, phone))
    if not phone.startswith('+'):
        return '+' + digits
    return '+' + digits


def fetch_disposable_domains() -> Set[str]:
    """
    Fetch disposable email domains from GitHub.
    Falls back to a comprehensive hardcoded list if fetch fails.
    
    Returns:
        Set of disposable email domains
    """
    urls = [
        "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt",
        "https://raw.githubusercontent.com/ivolo/disposable-email-domains/master/index.json",
    ]
    
    # Comprehensive fallback list with common temporary email domains
    fallback_domains = {
        # Popular temporary email services
        "10minutemail.com", "tempmail.com", "guerrillamail.com",
        "mailinator.com", "throwaway.email", "temp-mail.org",
        "getnada.com", "mohmal.com", "yopmail.com", "maildrop.cc",
        "tempmail.net", "tempail.com", "trashmail.com", "throwawaymail.com",
        "fakemail.net", "fakeinbox.com", "dispostable.com", "mintemail.com",
        "meltmail.com", "spamgourmet.com", "spamhole.com", "spamtraps.com",
        "tempinbox.com", "tempr.email", "tmpmail.org", "tmpmail.net",
        "throwaway.email", "throwawaymail.com", "throwawaymail.org",
        "guerrillamailblock.com", "guerrillamail.com", "guerrillamail.net",
        "guerrillamail.org", "guerrillamail.de", "pokemail.net",
        "spam4.me", "bccto.me", "chacuo.net", "dispostable.com",
        "emailondeck.com", "fake-box.com", "fakemailgenerator.com",
        "getairmail.com", "inboxkitten.com", "mailcatch.com",
        "maildrop.cc", "mailinator.com", "mailinator.net",
        "mintemail.com", "mohmal.com", "mytrashmail.com",
        "nada.email", "nada.ltd", "putthisin.com",
        "sharklasers.com", "spamgourmet.com", "temp-mail.io",
        "temp-mail.org", "tempail.com", "tempinbox.co.uk",
        "tempmail.com", "tempmail.de", "tempmail.eu",
        "tempmail.it", "tempmail.net", "tempmail.org",
        "tempmailaddress.com", "tempmailer.com", "tempmailo.com",
        "tempomail.fr", "throwaway.email", "throwawaymail.com",
        "trashmail.com", "trashmail.net", "trashmail.org",
        "yopmail.com", "yopmail.fr", "yopmail.net",
        # Additional common ones
        "33mail.com", "7tags.com", "adadres.com", "agedmail.com",
        "ama-trade.de", "amilegit.com", "anonymbox.com", "antichef.com",
        "antichef.net", "antireg.ru", "armyspy.com", "beefmilk.com",
        "bigstring.com", "binkmail.com", "bio-muesli.net", "bobmail.info",
        "bofthew.com", "brefmail.com", "broadbandninja.com", "bsnow.net",
        "bugmenot.com", "bumpymail.com", "bund.us", "burnthespam.info",
        "buymoreplays.com", "byom.de", "card.zp.ua", "casualdx.com",
        "cbair.com", "centermail.com", "centermail.net", "chammy.info",
        "cheatmail.de", "chogmail.com", "choicemail1.com", "clixser.com",
        "cmail.com", "cmail.net", "cmail.org", "coldmail.info",
        "consumerriot.com", "cool.fr.nf", "correotemporal.org", "cosmorph.com",
        "courriel.fr.nf", "courrieltemporaire.com", "crapmail.org",
        "crazymailing.com", "curryworld.de", "cust.in", "d3p.dk",
        "dacoolest.com", "dandikmail.com", "dayrep.com", "deadaddress.com",
        "deadspam.com", "delikkt.de", "despam.it", "despammed.com",
        "devnullmail.com", "dfgh.net", "digitalsanctuary.com", "dingbone.com",
        "discard.email", "discardmail.com", "discardmail.de", "disposableaddress.com",
        "disposableemailaddresses.com", "disposableinbox.com", "dispostable.com",
        "dm.w3internet.co.uk", "dodgeit.com", "dodgit.com", "dodgit.org",
        "doiea.com", "domozmail.com", "donemail.ru", "dontreg.com",
        "dontsendmespam.de", "dotmsg.com", "drdrb.com", "drdrb.net",
        "droplar.com", "dropmail.me", "duam.net", "dudmail.com",
        "dump-email.info", "dumpandjunk.com", "dumpyemail.com", "e4ward.com",
        "easytrashmail.com", "einmalmail.de", "einrot.com", "eintagsmail.de",
        "email60.com", "emailias.com", "emailinfive.com", "emailmiser.com",
        "emailsensei.com", "emailtemporar.ro", "emailwarden.com", "emailxfer.com",
        "emeil.ir", "emeil.ir", "emkei.cf", "emkei.ga", "emkei.gq",
        "emkei.ml", "emkei.tk", "eml.cc", "emltmp.com", "emz.net",
        "enterto.com", "ephemail.net", "epost.de", "ero-tube.org",
        "etranquil.com", "etranquil.net", "etranquil.org", "evopo.com",
        "explodemail.com", "express.net.ua", "eyepaste.com", "fake-box.com",
        "fakemail.fr", "fakemailgenerator.com", "fakemailz.com", "fammix.com",
        "fansworldwide.de", "fastacura.com", "fastchevy.com", "fastkawasaki.com",
        "fastmazda.com", "fastmitsubishi.com", "fastnissan.com", "fastsubaru.com",
        "fastsuzuki.com", "fasttoyota.com", "fastyamaha.com", "filzmail.com",
        "fizmail.com", "fleckens.hu", "frapmail.com", "freakmail.de",
        "free-email.cf", "free-email.ga", "free-email.gq", "free-email.ml",
        "free-email.tk", "freundin.ru", "friendlymail.co.uk", "front14.org",
        "fuckingduh.com", "fudgerub.com", "fux0ringduh.com", "garliclife.com",
        "gehensiemirnichtaufdensack.de", "gelitik.in", "get-mail.cf", "get-mail.ga",
        "get-mail.gq", "get-mail.ml", "get-mail.tk", "get1mail.com",
        "getairmail.com", "getmails.eu", "getonemail.com", "getonemail.net",
        "ghosttexter.de", "giantmail.de", "girlsundertheinfluence.com",
        "gishpuppy.com", "gmial.com", "goemailgo.com", "gotmail.com",
        "gotmail.net", "gotmail.org", "gotti.otherinbox.com", "gowikibooks.com",
        "gowikicampus.com", "gowikicars.com", "gowikifilms.com", "gowikigames.com",
        "gowikimusic.com", "gowikinetwork.com", "gowikitravel.com", "gowikitv.com",
        "grandmamail.com", "grandmasmail.com", "great-host.in", "greensloth.com",
        "grr.la", "gsrv.co.uk", "guerillamail.biz", "guerillamail.com",
        "guerillamail.de", "guerillamail.info", "guerillamail.net",
        "guerillamail.org", "guerillamailblock.com", "gustr.com", "h8s.org",
        "hacccc.com", "haltospam.com", "harakirimail.com", "hartbot.de",
        "hat-geld.de", "hatespam.org", "hellodream.mobi", "herp.in",
        "hidemail.de", "hidzz.com", "hmamail.com", "hochsitze.com",
        "hopemail.biz", "hotpop.com", "hulapla.de", "iaoss.com",
        "ibm.coms.hk", "ieatspam.eu", "ieatspam.info", "ieh-mail.de",
        "ihateyoualot.info", "iheartspam.org", "ikbenspamvrij.nl", "imails.info",
        "imstations.com", "inbax.tk", "inbox.si", "inboxalias.com",
        "inboxclean.com", "inboxclean.org", "incognitomail.com", "incognitomail.net",
        "incognitomail.org", "insorg-mail.info", "instant-mail.de", "ip6.li",
        "ipoo.org", "irish2me.com", "iroid.com", "isnotvalid.com",
        "ispyco.ru", "itmtx.com", "jetable.com", "jetable.fr.nf",
        "jetable.net", "jetable.org", "jnxjn.com", "jourrapide.com",
        "jsrsolutions.com", "junk1e.com", "kasmail.com", "kaspop.com",
        "keepmymail.com", "killmail.com", "killmail.net", "kir.ch.tc",
        "klassmaster.com", "klassmaster.net", "klzlk.com", "kook.ml",
        "koszmail.pl", "kulturbetrieb.info", "kurzepost.de", "l33r.eu",
        "lackmail.net", "lags.us", "landmail.co", "lastmail.co",
        "lazyinbox.com", "leeching.net", "letmeinonthis.com", "lifebyfood.com",
        "link2mail.net", "litedrop.com", "liveradio.tk", "lolfreak.net",
        "lookugly.com", "lopl.co.cc", "lortemail.dk", "lovemeleaveme.com",
        "lpfmgmtltd.com", "lr78.com", "lroid.com", "lukop.dk",
        "m21.cc", "m4ilweb.info", "maboard.com", "mail-filter.com",
        "mail-temporaire.fr", "mail.by", "mail.mezimages.net", "mail114.net",
        "mail15.com", "mail1a.de", "mail2000.ru", "mail2rss.org",
        "mail333.com", "mail4trash.com", "mailbidon.com", "mailbiz.biz",
        "mailblocks.com", "mailbucket.org", "mailcat.biz", "mailcatch.com",
        "mailde.de", "mailde.info", "maildrop.cc", "maildx.com",
        "maileater.com", "mailexpire.com", "mailfa.tk", "mailforspam.com",
        "mailfreeonline.com", "mailguard.me", "mailimate.com", "mailin8r.com",
        "mailinater.com", "mailinator.com", "mailinator.net", "mailinator.org",
        "mailinator2.com", "mailinblack.com", "mailincubator.com", "mailismagic.com",
        "mailme.lv", "mailme24.com", "mailmetrash.com", "mailmoat.com",
        "mailms.com", "mailnator.com", "mailnull.com", "mailorg.org",
        "mailpick.biz", "mailproxsy.com", "mailsac.com", "mailscrap.com",
        "mailseal.de", "mailshell.com", "mailsiphon.com", "mailslapping.com",
        "mailsucker.net", "mailtemp.info", "mailtome.de", "mailtothis.com",
        "mailtrash.net", "mailtv.net", "mailtv.tv", "mailzi.com",
        "makemetheking.com", "manifestgenerator.com", "manybrain.com", "mbx.cc",
        "mega.zik.dj", "meinspamschutz.de", "meltmail.com", "messagebeamer.de",
        "mezimages.net", "mierdamail.com", "migumail.com", "mintemail.com",
        "mjukglass.nu", "moakt.com", "moburl.com", "mohmal.com",
        "monemail.fr.nf", "monumentmail.com", "moot.es", "mox.pp.ua",
        "ms9.mailsfree.com", "msa.minsmail.com", "mspeciosa.com", "msxd.com",
        "mt2009.com", "mt2014.com", "mt2015.com", "muellemail.com",
        "mufux.com", "mugglenet.org", "mvrht.com", "mwarner.org",
        "mx0.wwwnew.eu", "my10minutemail.com", "mycard.net.ua", "mydemo.eql.com",
        "myemailboxy.com", "mymail-in.net", "mymailo.com", "mynetstore.de",
        "mypacks.net", "mypartyclip.de", "myphantomemail.com", "mysamp.de",
        "myspaceinc.com", "myspaceinc.net", "myspaceinc.org", "myspacepimpedup.com",
        "myspamless.com", "mytemp.email", "mytempemail.com", "mytempmail.com",
        "mytrashmail.com", "nabuma.com", "neomailbox.com", "nepwk.com",
        "nervmich.net", "nervtmich.net", "netmails.com", "netmails.net",
        "netzidiot.de", "neverbox.com", "nice-4u.com", "nincsmail.com",
        "nnh.com", "nobulk.com", "nobuma.com", "noclickemail.com",
        "nodezine.com", "nomail.cf", "nomail.ga", "nomail.gq",
        "nomail.ml", "nomail.tk", "nomail2me.com", "nomorespamemails.com",
        "nospam.ze.tc", "nospam4.us", "nospamfor.us", "nospamthanks.com",
        "notmailinator.com", "notsharingmy.info", "now.im", "nowhere.org",
        "nowmymail.com", "ntlhelp.net", "nurfuerspam.de", "nus.edu.sg",
        "nwldx.com", "objectmail.com", "obobbo.com", "odaymail.com",
        "odnorazovoe.ru", "one-time.email", "onewaymail.com", "online.ms",
        "oopi.org", "opayq.com", "ordinaryamerican.net", "oshietechan.link",
        "otherinbox.com", "ourklips.com", "outlawspam.com", "ovpn.to",
        "owlpic.com", "pancakemail.com", "paplease.com", "pcusers.otherinbox.com",
        "pepbot.com", "pfui.ru", "pimpedupmyspace.com", "pjkh.com",
        "plexolan.de", "poczta.onet.pl", "politikerclub.de", "poofy.org",
        "pookmail.com", "pop3.xyz", "postacin.com", "postfach2go.de",
        "postonline.me", "powered.name", "privacy.net", "privatdemail.net",
        "privy-mail.com", "privymail.de", "proxymail.eu", "prtnx.com",
        "prtz.eu", "punkass.com", "putthisin.com", "pwrby.com",
        "quickinbox.com", "quickmail.nl", "rcpt.at", "recode.me",
        "recursor.net", "recyclemail.dk", "regbypass.com", "regbypass.comsafe-mail.net",
        "rejectmail.com", "reliable-mail.com", "remail.cf", "remail.ga",
        "remail.gq", "remail.ml", "remail.tk", "rhyta.com",
        "rklips.com", "rmqkr.net", "robertspcrepair.com", "ronnierage.net",
        "rotfl.com", "rppkn.com", "rtrtr.com", "s0ny.net",
        "safe-mail.net", "safetymail.info", "safetypost.de", "sandelf.de",
        "saynotospams.com", "schafmail.de", "schmeissweg.tk", "schrott-email.de",
        "secretemail.de", "secure-mail.biz", "selfdestructingmail.com", "sendspamhere.com",
        "senseless-entertainment.com", "servermaps.net", "services391.com", "sharklasers.com",
        "shieldemail.com", "shiftmail.com", "shitmail.me", "shortmail.net",
        "showslow.de", "sibmail.com", "sinnlos-mail.de", "siteposter.net",
        "skeefmail.com", "slaskpost.se", "slipry.net", "slopsbox.com",
        "smellfear.com", "smellrear.com", "snakemail.com", "sneakemail.com",
        "snkmail.com", "sofimail.com", "sofort-mail.de", "soodonims.com",
        "spam.la", "spam.su", "spam4.me", "spamail.de",
        "spambob.com", "spambob.net", "spambob.org", "spambog.com",
        "spambog.de", "spambog.net", "spambog.ru", "spambox.info",
        "spambox.irishspringrealty.com", "spambox.us", "spamcannon.com", "spamcannon.net",
        "spamcero.com", "spamcon.org", "spamcorptastic.com", "spamcowboy.com",
        "spamcowboy.net", "spamcowboy.org", "spamday.com", "spamex.com",
        "spamfree24.com", "spamfree24.de", "spamfree24.eu", "spamfree24.info",
        "spamfree24.net", "spamfree24.org", "spamfree24.ru", "spamfree24.us",
        "spamgourmet.com", "spamgourmet.net", "spamgourmet.org", "spamherelots.com",
        "spamhereplease.com", "spamhole.com", "spamify.com", "spaminator.com",
        "spamkill.info", "spaml.com", "spaml.de", "spammail.me",
        "spammotel.com", "spamobox.com", "spamoff.de", "spamslicer.com",
        "spamspot.com", "spamstack.net", "spamthis.co.uk", "spamthisplease.com",
        "spamtraps.com", "spamtroll.net", "speed.1s.fr", "speedpost.net",
        "spikio.com", "spoofmail.de", "spybox.de", "squizzy.de",
        "sriaus.com", "stinkefinger.net", "stop-my-spam.com", "stuffmail.de",
        "super-auswahl.de", "supergreatmail.com", "supermailer.jp", "superrito.com",
        "superstachel.de", "suremail.info", "svk.jp", "sweetville.net",
        "tagyourself.com", "talkinator.com", "tapchicuoihoi.com", "teewars.org",
        "teleosaurs.xyz", "teleworm.com", "temp-mail.org", "temp-mail.ru",
        "tempail.com", "tempalias.com", "tempe-mail.com", "tempemail.biz",
        "tempemail.com", "tempinbox.co.uk", "tempinbox.com", "tempmail.com",
        "tempmail.de", "tempmail.eu", "tempmail.it", "tempmail.net",
        "tempmail.org", "tempmail2.com", "tempmailer.com", "tempmailer.de",
        "tempmailo.com", "tempomail.fr", "temporarily.de", "temporarioemail.com.br",
        "tempthe.net", "tempymail.com", "thanksnospam.info", "thankyou2010.com",
        "thecloudindex.com", "thisisnotmyrealemail.com", "throwaway.email", "throwawaymail.com",
        "throwawaymail.org", "tilien.com", "tmail.ws", "tmailinator.com",
        "toiea.com", "tradermail.info", "trash-amil.com", "trash-mail.at",
        "trash-mail.com", "trash-mail.de", "trash2009.com", "trashemail.de",
        "trashmail.at", "trashmail.com", "trashmail.de", "trashmail.me",
        "trashmail.net", "trashmail.org", "trashmailer.com", "trashymail.com",
        "trialmail.de", "trillianpro.com", "turual.com", "twinmail.de",
        "tyldd.com", "uggsrock.com", "umail.net", "upliftnow.com",
        "uplipht.com", "uroid.com", "us.af", "venompen.com",
        "veryrealemail.com", "viditag.com", "viewcastmedia.com", "viewcastmedia.net",
        "viewcastmedia.org", "webemail.me", "webm4il.info", "webuser.in",
        "wh4f.org", "whyspam.me", "willselfdestruct.com", "winemaven.info",
        "wronghead.com", "wuzup.net", "wuzupmail.net", "xagloo.com",
        "xemaps.com", "xents.com", "xmaily.com", "xoxy.net",
        "yapped.net", "yeah.net", "yep.it", "yogamaven.com",
        "yopmail.com", "yopmail.fr", "yopmail.net", "youmailr.com",
        "ypmail.webnastaran.com", "zippymail.info", "zoemail.org", "zoemail.net",
        "zomg.info", "zoemail.org", "zoemail.net", "zomg.info"
    }
    
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                if url.endswith('.json'):
                    domains = set(response.json())
                else:
                    domains = set(line.strip().lower() for line in response.text.split('\n') if line.strip())
                if domains:
                    logger.info(f"Loaded {len(domains)} disposable domains from {url}")
                    # Merge with fallback to ensure we have comprehensive coverage
                    domains.update(fallback_domains)
                    return domains
        except Exception as e:
            logger.warning(f"Failed to fetch from {url}: {e}")
            continue
    
    logger.warning(f"Using fallback disposable domains list ({len(fallback_domains)} domains)")
    return fallback_domains


def is_temporary_email(email: str) -> bool:
    """
    Check if email is from a temporary/disposable domain.
    Handles subdomains (e.g., user@mail.tempmail.com checks tempmail.com).
    
    Args:
        email: Email address to check
        
    Returns:
        True if email is temporary
    """
    global DISPOSABLE_DOMAINS
    if not DISPOSABLE_DOMAINS:
        # Initialize if not already loaded
        DISPOSABLE_DOMAINS = fetch_disposable_domains()
        logger.info(f"Initialized {len(DISPOSABLE_DOMAINS)} disposable domains")
    
    if '@' not in email:
        return False
    
    # Extract domain and convert to lowercase
    domain = email.split('@')[1].lower().strip()
    
    if not domain:
        return False
    
    # Check exact domain match
    if domain in DISPOSABLE_DOMAINS:
        logger.debug(f"Temporary email detected (exact match): {email} -> {domain}")
        return True
    
    # Check subdomain matches (e.g., mail.tempmail.com -> check tempmail.com)
    domain_parts = domain.split('.')
    if len(domain_parts) > 2:
        # Try parent domains (e.g., mail.tempmail.com -> tempmail.com)
        for i in range(1, len(domain_parts)):
            parent_domain = '.'.join(domain_parts[i:])
            if parent_domain in DISPOSABLE_DOMAINS:
                logger.debug(f"Temporary email detected (subdomain match): {email} -> {parent_domain}")
                return True
    
    return False


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of a string.
    
    Args:
        text: Input string
        
    Returns:
        Entropy value (bits per character)
    """
    if not text:
        return 0.0
    
    # Count character frequencies
    char_counts = {}
    for char in text.lower():
        char_counts[char] = char_counts.get(char, 0) + 1
    
    # Calculate entropy manually (replacing scipy.stats.entropy)
    length = len(text)
    entropy_value = 0.0
    for count in char_counts.values():
        if count > 0:
            prob = count / length
            entropy_value -= prob * math.log2(prob)
    
    return entropy_value


def extract_features(email: str) -> List[float]:
    """
    Extract numerical features from email for ML model.
    Matches the 11-feature vector from the training script.
    """
    local_part = email.split('@')[0].lower() if '@' in email else email.lower()
    
    length = len(local_part)
    digit_count = sum(c.isdigit() for c in local_part)
    letter_count = sum(c.isalpha() for c in local_part)
    special_count = length - digit_count - letter_count
    
    digit_ratio = digit_count / length if length > 0 else 0
    letter_ratio = letter_count / length if length > 0 else 0
    special_ratio = special_count / length if length > 0 else 0
    
    # New features for "Smarter" Model
    vowels = set("aeiou")
    vowel_count = sum(1 for c in local_part if c in vowels)
    vowel_ratio = vowel_count / letter_count if letter_count > 0 else 0
    
    has_dot = 1 if "." in local_part else 0
    has_underscore = 1 if "_" in local_part else 0
    
    max_consecutive_digits = 0
    current_consecutive = 0
    for char in local_part:
        if char.isdigit():
            current_consecutive += 1
            max_consecutive_digits = max(max_consecutive_digits, current_consecutive)
        else:
            current_consecutive = 0
            
    entropy = calculate_entropy(local_part)
    
    # Keyword check (binary feature)
    has_keyword = 1 if any(kw in local_part for kw in SPAM_KEYWORDS) else 0
    
    return [
        float(length), 
        float(digit_count), 
        float(digit_ratio), 
        float(letter_ratio), 
        float(special_ratio), 
        float(vowel_ratio),
        float(has_dot),
        float(has_underscore),
        float(max_consecutive_digits),
        float(entropy), 
        float(has_keyword)
    ]


def load_spam_model():
    """
    Load the pre-trained Random Forest model.
    """
    global SPAM_MODEL
    if SPAM_MODEL is None:
        try:
            if os.path.exists(MODEL_PATH):
                SPAM_MODEL = joblib.load(MODEL_PATH)
                logger.info(f"Random Forest model loaded from {MODEL_PATH}")
            else:
                logger.warning(f"Model file not found at {MODEL_PATH}. Falling back to rule-based detection.")
        except Exception as e:
            logger.error(f"Error loading ML model: {e}")
    return SPAM_MODEL


def calculate_spam_score(email: str) -> Tuple[int, str]:
    """
    Calculate spam score for an email (0-100).
    
    Args:
        email: Email address to score
        
    Returns:
        Tuple of (score, notes)
    """
    score = 0
    notes = []
    local_part = email.split('@')[0].lower() if '@' in email else email.lower()
    
    # Try to use Random Forest model first
    model = load_spam_model()
    if model is not None:
        try:
            features = extract_features(email)
            # Prediction probability for class 1 (Abuse)
            # model.predict_proba returns [[prob_0, prob_1]]
            prob = model.predict_proba([features])[0][1]
            score = int(prob * 100)
            notes.append(f"Random Forest prediction: {score}%")
            
            # If score is very high from ML, we can return early or combine
            if score > 80:
                return score, "; ".join(notes)
        except Exception as e:
            logger.error(f"ML Model prediction failed: {e}")
            notes.append("ML detection failed, using rules")

    # Heuristic fallback/combination logic
    # (Original rules remain as fallback or secondary validation)
    rule_score = 0
    
    # Check for spam keywords
    for keyword in SPAM_KEYWORDS:
        if keyword in local_part:
            rule_score += 25
            notes.append(f"Rule Match: Keyword '{keyword}'")
            break
    
    # digit check
    digit_count = sum(c.isdigit() for c in local_part)
    total_chars = len(local_part)
    if total_chars > 0:
        digit_ratio = digit_count / total_chars
        if digit_ratio > 0.7 and digit_count > 6:
            rule_score += 20
            notes.append("Rule Match: High numerical ratio")

    # entropy
    local_entropy = calculate_entropy(local_part)
    if local_entropy > 3.8:
        rule_score += 30
        notes.append("Rule Match: High entropy")

    # Final score is a mix or the maximum of both if ML is available
    final_score = max(score, min(rule_score, 100))
    
    return final_score, "; ".join(notes) if notes else "No issues detected"


def is_flagged_spam(spam_score: int) -> bool:
    """
    Determine if email should be flagged based on spam score.
    
    Args:
        spam_score: Spam score (0-100)
        
    Returns:
        True if score > 70
    """
    return spam_score > 70


def initialize_disposable_domains():
    """Initialize disposable domains list on startup."""
    global DISPOSABLE_DOMAINS
    DISPOSABLE_DOMAINS = fetch_disposable_domains()
    logger.info(f"Initialized {len(DISPOSABLE_DOMAINS)} disposable email domains")

