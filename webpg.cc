/**********************************************************\
Original Author: Kyle L. Huff (kylehuff)

Created:    Jan 14, 2011
License:    GNU General Public License, version 2
            http://www.gnu.org/licenses/gpl-2.0.html

Copyright 2013 Kyle L. Huff, CURETHEITCH development team
\**********************************************************/

#include "webpg.h"

#ifdef H_EMSCRIPTEN
#include "webpg-emsc.h"
#endif

/*
 * Define non-member constants/methods/inlines
 */
#ifdef HAVE_W32_SYSTEM
#define __func__ __FUNCTION__
#endif

// GNUGPGHOME need only be populated and all future context init's will use
//  the path as homedir for gpg
std::string GNUPGHOME;
std::string GNUPGBIN;
std::string GPGCONFHOME;
std::string GPGCONFBIN;

#ifdef H_webpgPluginPLUGIN
unsigned int WEBPG_PLUGIN_TYPE = WEBPG_PLUGIN_TYPE_NPAPI;
#else
unsigned int WEBPG_PLUGIN_TYPE = WEBPG_PLUGIN_TYPE_CLI;
#endif

// A global holder for the current edit_fnc status
std::string edit_status;

/* Global variables for the handling of UID signing or
    deleting signatures on UIDs */

// subkey_type
std::string gen_subkey_type;

// subkey_length
std::string gen_subkey_length;

// subkey_expire
std::string gen_subkey_expire;

// Flags for subkey generation
bool gen_sign_flag;
bool gen_enc_flag;
bool gen_auth_flag;

// index number of the UID which contains the signature to delete/revoke
std::string current_uid;

// index number for the signature to select
std::string current_sig;

// trust value to assign
std::string trust_assignment;

// uid name to create
std::string genuid_name;

// uid email to assign
std::string genuid_email;

// uid comment to assign
std::string genuid_comment;

// Used as iter count for current signature index
static int signature_iter;

// Used as iter count for current notation/description line
static int text_line;

// Used to store the index for the key/subkey
//  0: Public Key
//  1 &>: Subkeys
std::string akey_index;

// Used to store the value for the new expiration
std::string expiration;

// Used to store the type of item to revoke
std::string revitem;

// Used to store the index of the of the revocation reason
// 0: No reason specified
// 1: Key has been compromised
// 2: Key is superseded
// 3: Key is no longer used
// -- UID revocation --
// 4: User ID is no longer used
std::string reason_index;

// Used to store the revocation description
std::string description;

// Used to specify the path to an image
std::string photo_path;

// Used to keep track of the current edit iteration
static int step = 0;
static int jstep = 0;
static int flag_step = 0;

ssize_t write_res;

// Used to indicate the current edit action before calling edit_fnc
static int current_edit = WEBPG_EDIT_NONE;

GENKEY_PROGRESS_CB g_callback;
STATUS_PROGRESS_CB s_callback;
int EXTERNAL = 0;
std::string fnOutputString;
std::string original_gpg_config;
Json::Value webpg_status_map;

const char* WEBPG_EDIT_TYPE_STRINGS[] = {
  "WEBPG_EDIT_NONE",
  "WEBPG_EDIT_SIGN",
  "WEBPG_EDIT_DELSIGN",
  "WEBPG_EDIT_ENABLE",
  "WEBPG_EDIT_DISABLE",
  "WEBPG_EDIT_ADDSUBKEY",
  "WEBPG_EDIT_DELSUBKEY",
  "WEBPG_EDIT_ADD_UID",
  "WEBPG_EDIT_DEL_UID",
  "WEBPG_EDIT_SET_PRIMARY_UID",
  "WEBPG_EDIT_SET_KEY_EXPIRE",
  "WEBPG_EDIT_REVOKE_ITEM",
  "WEBPG_EDIT_PASSPHRASE",
  "WEBPG_EDIT_ASSIGN_TRUST",
  "WEBPG_EDIT_SHOW_PHOTO",
  "WEBPG_EDIT_CHECK_PHOTO",
  "WEBPG_EDIT_ADD_PHOTO"
};

const std::string EDIT_VALUES = "{\
  \"WEBPG_EDIT_SIGN\": {\
    \"keyedit.prompt\": [\
      \"fpr\",\
      \"_current_uid\",\
      \"tlsign\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_DELSIGN\": {\
    \"keyedit.prompt\": [\
      \"fpr\",\
      \"_current_uid\",\
      \"delsig\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_DISABLE\": {\
    \"keyedit.prompt\": [\
      \"disable\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_ENABLE\": {\
    \"keyedit.prompt\": [\
      \"enable\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_ASSIGN_TRUST\": {\
    \"keyedit.prompt\": [\
      \"trust\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_ADD_UID\": {\
    \"keyedit.prompt\": [\
      \"adduid\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_DEL_UID\": {\
    \"keyedit.prompt\": [\
      \"_current_uid\",\
      \"deluid\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_SET_PRIMARY_UID\": {\
    \"keyedit.prompt\": [\
      \"_current_uid\",\
      \"primary\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_SET_KEY_EXPIRE\": {\
    \"keyedit.prompt\": [\
      \"_key\",\
      \"expire\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_REVOKE_ITEM\": {\
    \"keyedit.prompt\": [\
      \"_item\",\
      \"_revitem\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_ADDSUBKEY\": {\
    \"keyedit.prompt\": [\
      \"addkey\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_DELSUBKEY\": {\
    \"keyedit.prompt\": [\
      \"_key\",\
      \"delkey\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_PASSPHRASE\": {\
    \"keyedit.prompt\": [\
      \"passwd\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_SHOW_PHOTO\": {\
    \"keyedit.prompt\": [\
      \"showphoto\",\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_CHECK_PHOTO\": {\
    \"keyedit.prompt\": [\
      \"quit\"\
    ]\
  },\
  \"WEBPG_EDIT_ADD_PHOTO\": {\
    \"keyedit.prompt\": [\
      \"addphoto\",\
      \"quit\"\
    ]\
  }\
}";

/* An inline method to convert an integer to a string */
inline
std::string i_to_str(const unsigned int &number)
{
  std::ostringstream oss;
  oss << number;
  return oss.str();
}

Json::Value get_error_map(
    const std::string& method,
    gpgme_error_t err,
    int line,
    const std::string& file,
    std::string data=""
) {
  Json::Value error_map_obj;
  error_map_obj["error"] = true;
  error_map_obj["method"] = method;
  error_map_obj["gpg_error_code"] = gpgme_err_code(err);
  char outbuf[512];
  gpgme_strerror_r(err, outbuf, 512);
  error_map_obj["error_string"] = outbuf;
  error_map_obj["line"] = line;
  error_map_obj["file"] = file;
  if (data.length())
    error_map_obj["data"] = data;
  return error_map_obj;
}

/* An inline method to convert a null char */
inline static const char* nonnull (const char *s)
{
  return s? s :"[none]";
}

std::string LoadFileAsString(const std::string& filename)
{
  std::ifstream fin(filename.c_str());

  if(!fin) {
    return "";
  }

  std::ostringstream oss;
  oss << fin.rdbuf();

  return oss.str();
}

// Create a dummy passphrase callback for instances where we cannot prevent
//  the agent from prompting the user when we are merely attempting to verify
//  a PGP block (this is needed for GPG2 on Windows)
gpgme_error_t passphrase_cb (
    void *opaque,
    const char *uid_hint,
    const char *passphrase_info,
    int last_was_bad,
    int fd
) {
  gpgme_io_write (fd, "\n", 1);
  return 0;
}

// Converts a "_param" to an actual value
std::string get_value_for(const char* var)
{
  std::string cmd;
  if (!strcmp(var, "_current_uid"))
    return current_uid.c_str();
  else if (!strcmp(var, "_key")) {
    cmd = "key ";
    cmd += akey_index;
    return cmd.c_str();
  } else if (!strcmp(var, "_item")) {
    if (!strcmp (revitem.c_str(), "revkey")) {
      cmd = "key ";
      cmd += akey_index;
    } else if (!strcmp (revitem.c_str(), "revuid")) {
      cmd = "uid ";
      cmd += current_uid;
    } else if (!strcmp (revitem.c_str(), "revsig")) {
      cmd = "uid ";
      cmd += current_uid;
    }
    return cmd.c_str();
  } else if (!strcmp(var, "_revitem"))
    return revitem.c_str();
  else
    return "ERROR";
}

gpgme_error_t edit_fnc(
  void *opaque,
    gpgme_status_code_t status,
    const char *args,
    int fd
) {
  /* this stores the response to a questions that arise during
     the edit loop - it is what the user would normally type while
     using `gpg --edit-key`. To test the prompts and their output,
     you can execute GnuPG this way:
         gpg --command-fd 0 --status-fd 2 --edit-key <KEY ID>
  */
  Json::Value EDIT_ACTIONS_MAP;
  Json::Reader _action_reader;
  if (false == (_action_reader.parse (EDIT_VALUES, EDIT_ACTIONS_MAP))) {
    std::cerr << "\nFailed to parse configuration:" <<
      _action_reader.getFormatedErrorMessages() << std::endl;
  }

  std::string response;
  int error = GPG_ERR_NO_ERROR;
  static std::string prior_response = "";
  static gpgme_status_code_t status_result;

  if (current_edit == WEBPG_EDIT_SIGN && status != 49 && status != 51)
    status_result = status;

  const char* edit_type = WEBPG_EDIT_TYPE_STRINGS[current_edit];

  // FIXME: Make this something useful
  if (!EDIT_ACTIONS_MAP.isMember(edit_type)) {
    std::cerr << "\nError: " << edit_type << " is not in EDIT_ACTIONS_MAP"
      << std::endl;
    return 1;
  }

  Json::Value default_value = "quit";
  Json::Value::ArrayIndex v_iter;

  if (fd >= 0) {
    if (!strcmp (args, "keyedit.prompt")) {
      switch (step) {
        case 0:
        case 1:
        case 2:
        case 3:
        case 4:
          if (EDIT_ACTIONS_MAP[edit_type]["keyedit.prompt"]
           .isValidIndex(step)) {
            v_iter = step;
            if (EDIT_ACTIONS_MAP[edit_type]["keyedit.prompt"]
             .get(v_iter, default_value).asString().substr(0, 1) == "_") {
              response = get_value_for(
                EDIT_ACTIONS_MAP[edit_type]["keyedit.prompt"]
                  .get(v_iter, default_value).asString().c_str()
              );
            } else {
              response = EDIT_ACTIONS_MAP[edit_type]["keyedit.prompt"]
               .get(v_iter, default_value).asString();
            }
            if (step == 1) {
              if (current_edit == WEBPG_EDIT_DELSIGN)
                signature_iter = 1;
              if (current_edit == WEBPG_EDIT_REVOKE_ITEM) {
                signature_iter = 0;
                text_line = 1;
              }
            }
            break;
          } else {
            step = -1;
            response = "quit";
            break;
          }

        default:
          if (status_result && prior_response == "tlsign")
            error = status_result; // there is a problem...
          prior_response = "";
          step = -1;
          response = "quit";
          break;
      }
      step++;
    }
    else if (!strcmp (args, "keyedit.save.okay"))
      response = "Y";
    else if (!strcmp (args, "trustsig_prompt.trust_value"))
      response = "1";
    else if (!strcmp (args, "trustsig_prompt.trust_depth"))
      response = "1";
    else if (!strcmp (args, "trustsig_prompt.trust_regexp"))
      response = "";
    else if (!strcmp (args, "sign_uid.okay"))
      response = "y";
    else if (!strcmp (args, "keyedit.delsig.valid") ||
             !strcmp (args, "keyedit.delsig.invalid") ||
             !strcmp (args, "keyedit.delsig.unknown") ||
             !strcmp (args, "ask_revoke_sig.one")) {
      if (signature_iter == atoi(current_sig.c_str())) {
        response = "y";
        current_sig = "0";
        current_uid = "0";
        signature_iter = 0;
      } else {
        response = "N";
      }
      signature_iter++;
    } else if (!strcmp (args, "edit_ownertrust.value")) {
      if (step < 15) {
        response = trust_assignment;
        step++;
      } else {
        response = "m";
      }
    } else if (!strcmp (args, "edit_ownertrust.set_ultimate.okay"))
      response = "Y";
    else if (!strcmp (args, "keyedit.delsig.selfsig"))
      response = "y";
    else if (!strcmp (args, "keygen.name"))
      response = genuid_name.c_str();
    else if (!strcmp (args, "keygen.email")) {
      if (strlen (genuid_email.c_str()) > 1)
        response = genuid_email.c_str();
      else
        response = "";
    } else if (!strcmp (args, "keygen.comment")) {
      if (strlen (genuid_comment.c_str()) > 1)
        response = genuid_comment.c_str();
      else
        response = "";
    } else if (!strcmp (args, "keygen.algo"))
      response = gen_subkey_type.c_str();
    else if (!strcmp (args, "keygen.flags")) {
      switch (flag_step) {
        case 0:
          // If the gen_sign_flag is set, we don't need to change
          //  anything, as the sign_flag is set by default
          if (gen_sign_flag) {
            response = "nochange";
          } else {
            response = "S";
          }
          break;

        case 1:
          // If the gen_enc_flag is set, we don't need to change
          //  anything, as the enc_flag is set by default on keys
          //  that support the enc flag (RSA)
          if (gen_enc_flag) {
            response = "nochange";
          } else {
            response = "E";
          }
          break;

        case 2:
          if (gen_auth_flag) {
            response = (char *) "A";
          } else {
            response = "nochange";
          }
          break;

        default:
          response = "Q";
          flag_step = -1;
          break;
      }
      flag_step++;
    } else if (!strcmp (args, "keygen.size"))
      response = gen_subkey_length.c_str();
    else if (!strcmp (args, "keygen.valid"))
      response = expiration.c_str();
    else if (!strcmp (args, "keyedit.remove.uid.okay"))
      response = "Y";
    else if (!strcmp (args, "keyedit.revoke.subkey.okay"))
      response = "Y";
    else if (!strcmp (args, "keyedit.revoke.uid.okay"))
      response = "Y";
    else if (!strcmp (args, "ask_revoke_sig.okay"))
      response = "Y";
    else if (!strcmp (args, "ask_revocation_reason.code"))
      response = reason_index.c_str();
    else if (!strcmp (args, "ask_revocation_reason.text")) {
      if (text_line > 1) {
        text_line = 1;
        response = "";
      } else {
        text_line++;
        response = description.c_str();
      }
    } else if (!strcmp (args, "ask_revocation_reason.okay"))
        response = "Y";
    else if (!strcmp (args, "keyedit.remove.subkey.okay"))
      response = "Y";
    else if (!strcmp (args, "photoid.jpeg.add")) {
      switch (jstep) {
        case 0:
          response = photo_path;
          break;

        default:
          jstep = -1;
          break;
      }
      jstep++;
    } else if (!strcmp (args, "photoid.jpeg.size"))
      response = "Y";
    else if (!strcmp (args, "keyedit.save.okay")) {
      response = "Y";
      step = 0;
    } else if (!strcmp (args, "passphrase.enter")) {
      response = "";
    } else {
      std::cerr << "We should never reach this line; Line: "
        << __LINE__ << std::endl
        << edit_status << std::endl << std::endl
        << "'" << args << "'" << std::endl;
      response = "quit";
    }
  } else {
    return 0;
  }

  prior_response = response;
  if (!strcmp(response.c_str(), "quit")) {
    step = 0;
    jstep = 0;
    flag_step = 0;
  }

  gpgme_io_write (fd, response.c_str(), response.length());
  gpgme_io_write (fd, "\n", 1);

  return error;
}

using namespace boost::archive::iterators;
using namespace mimetic;

///////////////////////////////////////////////////////////////////////////////
/// @fn webpg::webpg()
///
/// @brief  Constructor for the webpg object. Performs object initialization.
///////////////////////////////////////////////////////////////////////////////
//webpg::webpg()
//{
//  webpg::init();
//}

///////////////////////////////////////////////////////////////////////////////
/// @fn webpg::~webpg()
///
/// @brief  Destructor.
///////////////////////////////////////////////////////////////////////////////
//webpg::~webpg()
//{
//}

///////////////////////////////////////////////////////////////////////////////
/// @fn void init()
///
/// @brief  Initializes webpg and sets the status variables.
///////////////////////////////////////////////////////////////////////////////
void webpg::init()
{
  fnOutputString = "";
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  Json::Value error_map(Json::objectValue);
  Json::Value response(Json::objectValue);
  Json::Value protocol_info(Json::objectValue);
  Json::Value plugin_info(Json::objectValue);
  gpgme_engine_info_t engine_info;

  plugin_info["version"] = WEBPG_VERSION_STRING;
  plugin_info["type"] =
        (WEBPG_PLUGIN_TYPE == WEBPG_PLUGIN_TYPE_CLI) ? "CLI"
      : (WEBPG_PLUGIN_TYPE == WEBPG_PLUGIN_TYPE_LIB) ? "LIB"
      : (WEBPG_PLUGIN_TYPE == WEBPG_PLUGIN_TYPE_NPAPI) ? "NPAPI"
      : (WEBPG_PLUGIN_TYPE == WEBPG_PLUGIN_TYPE_NATIVEHOST) ? "NATIVEHOST"
      : "UNKNOWN";

  size_t bufsize = 255;
  char *buf = new char[bufsize];

#ifdef HAVE_W32_SYSTEM
  GetModuleFileName(NULL, buf, bufsize);
#else
  ssize_t rres = readlink("/proc/self/exe", buf, bufsize);
  (void)rres;
#endif

  plugin_info["path"] = buf;

  response["plugin"] = plugin_info;

  /* Initialize the locale environment.
   * The function `gpgme_check_version` must be called before any other
   * function in the library, because it initializes the thread support
   * subsystem in GPGME. (from the info page) */
  std::string gpgme_version = (char *) gpgme_check_version(NULL);

  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

  ctx = get_gpgme_ctx();

  response["error"] = false;

  err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);
  if (err != GPG_ERR_NO_ERROR)
      error_map = get_error_map(__func__, err, __LINE__, __FILE__);

  if (error_map.size() > 0) {
      response["error"] = true;
      response["error_map"] = error_map;
      webpg_status_map = error_map;
  }

  response["gpgconf_detected"] = gpgconf_detected();
  response["openpgp_detected"] = openpgp_detected();

  response["gpgme_version"] = gpgme_version;

  engine_info = gpgme_ctx_get_engine_info (ctx);

  if (err == GPG_ERR_NO_ERROR) {
    while (engine_info) {
      if (engine_info->file_name)
        protocol_info["file_name"] = (char *) engine_info->file_name;
      if (engine_info->version)
        protocol_info["version"] = (char *) engine_info->version;
      if (engine_info->home_dir)
        protocol_info["home_dir"] = (char *) engine_info->home_dir;
      if (engine_info->req_version)
        protocol_info["req_version"] = (char *) engine_info->req_version;

      std::string proto_name =
        (engine_info->protocol == GPGME_PROTOCOL_OpenPGP) ? "OpenPGP"
          : (engine_info->protocol == GPGME_PROTOCOL_CMS) ? "CMS"
          : (engine_info->protocol == GPGME_PROTOCOL_GPGCONF) ? "GPGCONF"
          : (engine_info->protocol == GPGME_PROTOCOL_ASSUAN) ? "Assuan"
          : (engine_info->protocol == GPGME_PROTOCOL_G13) ? "G13"
          : (engine_info->protocol == GPGME_PROTOCOL_UISERVER) ? "UISERVER"
          : (engine_info->protocol == GPGME_PROTOCOL_UISERVER) ? "DEFAULT"
          : "UNKNOWN";

      response[proto_name] = protocol_info;
      protocol_info.clear();

      engine_info = engine_info->next;
    }
  }

  response["GNUPGHOME"] = GNUPGHOME;
  response["GNUPGBIN"] = GNUPGBIN;
  response["GPGCONFHOME"] = GPGCONFHOME;
  response["GPGCONFBIN"] = GPGCONFBIN;

  // Retrieve the GPG_AGENT_INFO environment variable
  char *gpg_agent_info = getenv("GPG_AGENT_INFO");

  if (gpg_agent_info != NULL) {
    response["gpg_agent_info"] = gpg_agent_info;
  } else {
    response["gpg_agent_info"] = "unknown";
  }

  if (ctx && err == GPG_ERR_NO_ERROR)
    gpgme_release (ctx);

  webpg_status_map = response;
};

#ifndef H_LIBWEBPG // Do not include this method when compiling the lib
void writeOut(const Json::Value str, const bool parse=false) {
  std::string ret;
#ifdef HAVE_W32_SYSTEM
  _setmode(_fileno(stdin),_O_BINARY);
#endif
  // if this is being called as a native-messaging host, we don't want
  //  to return a styled JSON string, as that is a waste of resources.
  if (WEBPG_PLUGIN_TYPE == WEBPG_PLUGIN_TYPE_NATIVEHOST) {
    if (parse == true) {
      Json::FastWriter writer;
      ret = writer.write(str);
    }

#ifdef HAVE_W32_SYSTEM
    // Remove all newlines on w32
    ret.erase(std::remove(ret.begin(), ret.end(), '\n'), ret.end());
#endif

    unsigned int a = ret.length();

    // We need to send the 4 btyes of length information
    std::cout << char(((a>>0) & 0xFF))
              << char(((a>>8) & 0xFF))
              << char(((a>>16) & 0xFF))
              << char(((a>>24) & 0xFF));
  } else {
    if (parse == true)
      ret = str.toStyledString();
  }

  std::cout << ret;
}

void nativeCallback(const char* type, const char* data)
{
  Json::Value ret(Json::objectValue);
  ret["type"] = type;
  ret["data"] = data;
  writeOut(ret, true);
}
#endif

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value get_version()
///
/// @brief  Retruns the defined plugin version
///////////////////////////////////////////////////////////////////////////////
// Read-only property version
Json::Value webpg::get_version()
{
  return WEBPG_VERSION_STRING;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn gpgme_ctx_t get_gpgme_ctx()
///
/// @brief  Creates the gpgme context with the required options.
///////////////////////////////////////////////////////////////////////////////
gpgme_ctx_t webpg::get_gpgme_ctx()
{
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  setlocale (LC_ALL, "");
  gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#ifdef LC_MESSAGES
  gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#endif

  std::string gpgme_version = (char *) gpgme_check_version(NULL);

  err = gpgme_new (&ctx);

  if (err != GPG_ERR_NO_ERROR)
    return ctx;

  gpgme_engine_info_t engine_info = gpgme_ctx_get_engine_info (ctx);

  if (engine_info) {
    gpgme_ctx_set_engine_info (ctx, GPGME_PROTOCOL_OpenPGP,
                               (GNUPGBIN.length() > 0) ?
                                 (char *) GNUPGBIN.c_str() : NULL,
                               (GNUPGHOME.length() > 0) ?
                                 (char *) GNUPGHOME.c_str() : NULL);
    gpgme_ctx_set_engine_info (ctx, GPGME_PROTOCOL_GPGCONF,
                               (GPGCONFBIN.length() > 0) ?
                                 (char *) GPGCONFBIN.c_str() : NULL,
                               (GPGCONFHOME.length() > 0) ?
                                 (char *) GPGCONFBIN.c_str() : NULL);
  } else {
    gpgme_new (&ctx);
  }

  gpgme_set_textmode (ctx, 1);
  gpgme_set_armor (ctx, 1);

  return ctx;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value get_webpg_status()
///
/// @brief  Executes webpg::init() to set the status variables and
///         populates the "edit_status" property with the contents of the
///         edit_status constant.
///
/// @returns Json::Value webpg_status_map
/*! @verbatim
webpg_status_map {
    "Assuan": {
        "file_name": "/tmp/keyring-3WPw3L/gpg",
        "home_dir": "!GPG_AGENT",
        "req_version": "1.0",
        "version": "1.0"
    },
    "GNUPGHOME": "",
    "GPGCONF": {
        "file_name": "/usr/bin/gpgconf",
        "req_version": "2.0.4",
        "version": "2.0.17"
    },
    "OpenPGP": {
        "file_name": "/usr/bin/gpg",
        "req_version": "1.4.0",
        "version": "1.4.11"
    },
    "edit_status": "",
    "error": false,
    "gpg_agent_info": "/tmp/keyring-3WPw3L/gpg:0:1",
    "gpgconf_detected": true,
    "gpgme_version": "1.3.2",
    "openpgp_detected": true
}
@endverbatim
*/
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::get_webpg_status()
{
    webpg::init();
    webpg::webpg_status_map["edit_status"] = edit_status;
    return webpg::webpg_status_map;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn bool openpgp_detected()
///
/// @brief  Determines if OpenPGP is available as a valid engine.
///////////////////////////////////////////////////////////////////////////////
bool webpg::openpgp_detected()
{
  gpgme_set_engine_info (GPGME_PROTOCOL_OpenPGP,
      (GNUPGBIN.length() > 0) ? (char *) GNUPGBIN.c_str() : NULL,
      (GNUPGHOME.length() > 0) ? (char *) GNUPGHOME.c_str() : NULL);
  gpgme_error_t err = gpgme_engine_check_version (GPGME_PROTOCOL_OpenPGP);

  if (err && err != GPG_ERR_NO_ERROR)
    return false;

  return true;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn bool gpgconf_detected()
///
/// @brief  Determines gpgconf is available to the engine.
///////////////////////////////////////////////////////////////////////////////
bool webpg::gpgconf_detected()
{
  gpgme_set_engine_info (GPGME_PROTOCOL_GPGCONF,
    (GPGCONFBIN.length() > 0) ? (char *) GPGCONFBIN.c_str() : NULL,
    (GPGCONFHOME.length() > 0) ? (char *) GPGCONFHOME.c_str() : NULL);
  gpgme_error_t err = gpgme_engine_check_version (GPGME_PROTOCOL_GPGCONF);

  if (err && err != GPG_ERR_NO_ERROR)
    return false;

  return true;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value getKeyList(const std::string& name, bool secret_only)
///
/// @brief  Retrieves all keys matching name, or if name is not specified,
///         returns all keys in the keyring. The keyring to use is determined
///         by the integer value of secret_only.
///
/// @param  name    Name of key to retrieve
/// @param  secret_only Return only secret keys (private keyring)
/// @returns Json::Value keylist_map
/*! @verbatim
keylist_map {
    "1E4F6A67ACD1C298":{
        "can_authenticate":true,
        "can_certify":true,
        "can_encrypt":true,
        "can_sign":true,
        "disabled":false,
        "email":"webpg.extension.devel@curetheitch.com",
        "expired":false,
        "fingerprint":"68634186B526CC1F959404401E4F6A67ACD1C298",
        "invalid":false,
        "is_qualified":false,
        "name":"WebPG Testing Key",
        "owner_trust":"marginal",
        "protocol":"OpenPGP",
        "revoked":false,
        "secret":false,
        "subkeys":{
            "0":{
                "algorithm":1,
                "algorithm_name":"RSA",
                "can_authenticate":true,
                "can_certify":true,
                "can_encrypt":true,
                "can_sign":true,
                "created":1311695391,
                "disabled":false,
                "expired":false,
                "expires":1382501753,
                "invalid":false,
                "is_qualified":false,
                "revoked":false,
                "secret":false,
                "size":2048,
                "subkey":"68634186B526CC1F959404401E4F6A67ACD1C298"
            },
            "1":{
                "algorithm":1,
                "algorithm_name":"RSA",
                "can_authenticate":true,
                "can_certify":false,
                "can_encrypt":true,
                "can_sign":true,
                "created":1311695391,
                "disabled":false,
                "expired":false,
                "expires":1382501780,
                "invalid":false,
                "is_qualified":false,
                "revoked":false,
                "secret":false,
                "size":2048,
                "subkey":"0C178DD984F837340075BD76C599711F5E82BB93"
            }
        },
        "uids":{
            "0":{
                "comment":"",
                "email":"extension.devel@webpg.org",
                "invalid":false,
                "revoked":false,
                "signatures":{
                    "0":{
                        "algorithm":1,
                        "algorithm_name":"RSA",
                        "comment":"",
                        "created":1344744953,
                        "email":"extension.devel@webpg.org",
                        "expired":false,
                        "expires":0,
                        "exportable":true,
                        "invalid":false,
                        "keyid":"1E4F6A67ACD1C298",
                        "name":"WebPG Testing Key",
                        "revoked":false,
                        "uid":"WebPG Testing Key <extension.devel@webpg.org>"
                    },
                    "1":{
                        "algorithm":17,
                        "algorithm_name":"DSA",
                        "comment":"",
                        "created":1315338021,
                        "email":"",
                        "expired":false,
                        "expires":0,
                        "exportable":false,
                        "invalid":false,
                        "keyid":"0DF9C95C3BE1A023",
                        "name":"Kyle L. Huff",
                        "revoked":false,
                        "uid":"Kyle L. Huff"
                    },
                },
                "signatures_count":2,
                "uid":"WebPG Testing Key",
                "validity":"full"
           }
       }
    }
}
@endverbatim
*/
///////////////////////////////////////////////////////////////////////////////
/*
    This method retrieves all keys matching name, or if name is left empty,
        returns all keys in the keyring.
*/
Json::Value webpg::getKeyList(
  const std::string& name,
  bool secret_only,
  bool fast=false,
  void* APIObj=NULL,
  void(*cb_status)(
    void *self,
    const char *msg
  )=NULL
) {
  if (cb_status != NULL)
    return webpg::getKeyListWorker(name, secret_only, fast, APIObj, cb_status);
  else
    return webpg::getKeyListWorker(name, secret_only, fast, NULL, NULL);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value getPublicKeyList()
///
/// @brief  Calls webpg::getKeyList() without specifying a search
///         string, and the secret_only paramter as false, which returns only
///         Public Keys from the keyring.
///////////////////////////////////////////////////////////////////////////////
/*
    This method executes webpg::getKeyList with an empty string and
        secret_only=false which returns all Public Keys in the keyring.
*/
Json::Value webpg::getPublicKeyList(
  bool fastListMode,
  bool async,
  STATUS_PROGRESS_CB callback
) {
  // Retrieve the public keylist
  if (callback && async == true) {
    s_callback = callback;
    getKeyList("", false, fastListMode, this, &webpg::status_progress_cb);
    return "queued";
#ifndef H_LIBWEBPG
  } else if (async == true) {
      s_callback = nativeCallback;
      getKeyList("", false, fastListMode, this, &webpg::status_progress_cb);
      return "queued";
#endif
  } else {
    return getKeyList("", false, fastListMode);
  }
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value getPrivateKeyList()
///
/// @brief  Calls webpg::getKeyList() without specifying a search
///         string, and the secret_only paramter as true, which returns only
///         Private Keys from the keyring.
///////////////////////////////////////////////////////////////////////////////
/*
    This method executes webpg::getKeyList with an empty string and
        secret_only=true which returns all keys in the keyring which
        the user has the corrisponding secret key.
*/
Json::Value webpg::getPrivateKeyList(
  bool fastListMode,
  bool async,
  STATUS_PROGRESS_CB callback
) {
  // Retrieve the private keylist
  if (callback && async == true) {
    s_callback = callback;
    getKeyList("", true, fastListMode, this, &webpg::status_progress_cb);
    return "queued";
#ifndef H_LIBWEBPG
  } else if (async == true) {
      s_callback = nativeCallback;
      getKeyList("", true, fastListMode, this, &webpg::status_progress_cb);
      return "queued";
#endif
  } else {
    // Retrieve the private keylist
    return getKeyList("", true, fastListMode);
  }
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value getNamedKey(const std::string& name)
///
/// @brief  Calls webpg::getKeyList() with a search string and the
///         secret_only paramter as false, which returns only Public Keys from
///         the keyring.
///////////////////////////////////////////////////////////////////////////////
/*
    This method just calls webpg::getKeyList with a name/email
        as the parameter
*/
Json::Value webpg::getNamedKey(const std::string& name,
                               const boost::optional<bool> fast=false)
{
  bool fastListMode = (fast==true);
  // Retrieve the named key from the keylist
  return getKeyList(name, false, fastListMode);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value getExternalKey(const std::string& name)
///
/// @brief  Calls getKeyList() after setting the context to
///         external mode with a search string and the secret_only paramter as
///         false, which returns only Public Keys
///////////////////////////////////////////////////////////////////////////////
/*
    This method just calls getKeyList with a name/email
        as the parameter
*/
Json::Value webpg::getExternalKey(const std::string& name)
{
  EXTERNAL = 1;

  // return the keylist
  return getKeyList(name, false);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn std::string get_preference(const std::string& preference)
///
/// @brief  Attempts to retrieve the specified preference from the gpgconf
///         utility.
///
/// @param  preference  The gpgconf preference to retrieve.
///////////////////////////////////////////////////////////////////////////////
std::string webpg::get_preference(const std::string& preference)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_conf_comp_t conf, comp;
  gpgme_conf_opt_t opt;
  std::string return_value;

  gpgme_op_conf_load (ctx, &conf);

  comp = conf;
  while (comp && strcmp (comp->name, "gpg"))
    comp = comp->next;

  if (comp) {
    opt = comp->options;

    while (opt && strcmp (opt->name, (char *) preference.c_str())){
      opt = opt->next;
    }

    if (opt->value) {
      return_value = opt->value->value.string;
    } else {
      return_value = "blank";
    }
  }

  gpgme_conf_release (conf);
  return return_value;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSetPreference(const std::string& preference,
///                                  const std::string& pref_value)
///
/// @brief  Attempts to set the specified gpgconf preference with the value
///         of pref_value.
///
/// @param  preference  The preference to set.
/// @param  pref_value  The value to assign to the specified preference.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSetPreference(
    const std::string& preference,
    const std::string& pref_value="blank"
) {
  gpgme_error_t err;
  gpgme_protocol_t proto = GPGME_PROTOCOL_OpenPGP;
  err = gpgme_engine_check_version (proto);

  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_conf_comp_t conf, comp;
  std::string return_code;

  err = gpgme_op_conf_load (ctx, &conf);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_conf_arg_t original_arg = NULL, arg = NULL;
  gpgme_conf_opt_t opt;

  if (pref_value.length())
    err = gpgme_conf_arg_new (&arg, GPGME_CONF_STRING,
                              (char *) pref_value.c_str());
  else
    err = gpgme_conf_arg_new (&arg, GPGME_CONF_STRING, NULL);

  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  comp = conf;
  while (comp && strcmp (comp->name, "gpg"))
    comp = comp->next;

  if (comp) {
    opt = comp->options;

    while (opt && strcmp (opt->name, (char *) preference.c_str())){
      opt = opt->next;
    }

    if (!opt) {
      return "unable to locate that option in this context";
    }

    original_arg = opt->value;

    if (!opt->value && pref_value.length() > 1) {
      return_code = "blank";
    }

    /* if the new argument and original argument are the same, return 0,
        there is nothing to do. */
    if (pref_value.length() && original_arg &&
      !strcmp (original_arg->value.string, arg->value.string)) {
      return "0";
    } else if (original_arg) {
      return_code = original_arg->value.string;
    }

    if (opt) {
      if (!strcmp(pref_value.c_str(), "blank") || pref_value.length() < 1)
        err = gpgme_conf_opt_change (opt, 0, NULL);
      else
        err = gpgme_conf_opt_change (opt, 0, arg);

      if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, err, __LINE__, __FILE__);

      err = gpgme_op_conf_save (ctx, comp);
      if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, err, __LINE__, __FILE__);

      if (preference == "group")
        return return_code;
    }
  }

  if (conf)
    gpgme_conf_release (conf);

  if (ctx)
    gpgme_release (ctx);

  return return_code;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgGetPreference(const std::string& preference)
///
/// @brief  Attempts to retrieve the specified preference from the gpgconf
///         utility.
///
/// @param  preference  The gpgconf preference to retrieve.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgGetPreference(const std::string& preference)
{
  gpgme_error_t err;
  gpgme_protocol_t proto = GPGME_PROTOCOL_OpenPGP;
  err = gpgme_engine_check_version (proto);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_conf_comp_t conf, comp;
  Json::Value response;
  response["error"] = false;
  std::string res;

  err = gpgme_op_conf_load (ctx, &conf);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_conf_arg_t arg;
  gpgme_conf_opt_t opt;

  comp = conf;
  while (comp && strcmp (comp->name, "gpg"))
    comp = comp->next;

  if (comp) {
    opt = comp->options;

    while (opt && strcmp (opt->name, (char *) preference.c_str())){
      opt = opt->next;
    }

    if (opt) {
      if (opt->value) {
        arg = opt->value;
        while (arg) {
          res += arg->value.string;
          arg = arg->next;
          if (arg)
              res += ", ";
        }
        response["value"] = res;
      } else {
        response["value"] = "";
      }
    } else {
      response["error"] = true;
      response["error_string"] = "unable to locate option in this context";
    }
  }

  if (conf)
    gpgme_conf_release (conf);

  if (ctx)
    gpgme_release (ctx);

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSetGroup(const std::string& group,
///                             const std::string& group_value)
///
/// @brief  Attempts to define or clear the specified group preference with the
///         value of <group_value>.
///
/// @param  group  The group to set.
/// @param  group_value  The value to assign to the specified group.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSetGroup(
    const std::string& group,
    const std::string& group_value=""
) {
  gpgme_error_t err;
  gpgme_protocol_t proto = GPGME_PROTOCOL_OpenPGP;
  err = gpgme_engine_check_version (proto);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_conf_comp_t conf, comp;
  Json::Value response;
  std::string return_code;
  bool modify_existing = false;
  bool value_exists = false;

  err = gpgme_op_conf_load (ctx, &conf);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_conf_arg_t original_arg, arg, temparg, last;
  gpgme_conf_opt_t opt;

  std::string group_arg = group;
  group_arg += " = ";
  group_arg += group_value;

  if (group_value.length())
    err = gpgme_conf_arg_new (&arg, GPGME_CONF_STRING,
                              (char *) group_arg.c_str());
  else
    err = gpgme_conf_arg_new (&arg, GPGME_CONF_STRING, NULL);

  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  comp = conf;
  while (comp && strcmp (comp->name, "gpg"))
    comp = comp->next;

  if (comp) {
    opt = comp->options;

    while (opt && strcmp (opt->name, "group")){
      opt = opt->next;
    }

    if (!opt) {
      return "unable to locate that option in this context";
    }

    original_arg = opt->value;

    if (!opt->value && group_value.length() > 1) {
      return_code = "blank";
    } else {
      return_code = original_arg->value.string;
    }

    std::string cgroup_value;
    std::string cgroup_name;
    // Determine the name of the target group
    cgroup_name = group_value.substr(0, group_value.find("=") - 1);

    if (original_arg) {
      // There are current groups defined, iterate through
      // the values and check if the named group exists
      while (original_arg) {
        cgroup_value = original_arg->value.string;
        // This is the target group, we will be modifying it
        if (cgroup_value.find(group + " =") != std::string::npos) {
          original_arg->value.string = (char *) group_arg.c_str();
          modify_existing = true;
          value_exists = true;
        } else {
          // Not the target group, add this arg to the option
          original_arg->value = original_arg->value;
        }
        last = original_arg;
        original_arg = original_arg->next;
      }
      if (!value_exists)
        if (group_value == "blank" || group_value.length() < 1)
          return get_error_map(__func__, GPG_ERR_VALUE_NOT_FOUND, __LINE__,
                               __FILE__);
      if (!modify_existing) {
        // Append the arg
        last->next = arg;
      }
    } else {
      if (group_value == "blank" || group_value.length() < 1)
        return "blank";
      opt->value = arg;
    }

    temparg = opt->value;
    while(temparg) {
      return_code += temparg->value.string;
      temparg = temparg->next;
      if (temparg) {
        return_code += ", ";
      }
    }

    /* if the new argument and original argument are the same, return 0,
        there is nothing to do. */
    if (group_value.length() && original_arg &&
      !strcmp (original_arg->value.string, arg->value.string)) {
      return "0";
    }

    if (opt) {
      arg = opt->value;

      err = gpgme_conf_opt_change (opt, 0, arg);

      if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, err, __LINE__, __FILE__);

      err = gpgme_op_conf_save (ctx, comp);
      if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, err, __LINE__, __FILE__);
    }
  }

  return return_code;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn std::string getGPGConfigFilename()
///
/// @brief  Attempts to determine the correct location of the gpg
///         configuration file.
///////////////////////////////////////////////////////////////////////////////
std::string webpg::getGPGConfigFilename()
{
  std::string config_path = "";

  if (GNUPGHOME.length() > 0) {
    config_path = GNUPGHOME;
  } else {
    char const* home = getenv("HOME");
    if (home || (home = getenv("USERPROFILE"))) {
      config_path = home;
    } else {
      char const *hdrive = getenv("HOMEDRIVE"),
        *hpath = getenv("HOMEPATH");
      assert(hdrive);  // or other error handling
      assert(hpath);
      config_path = std::string(hdrive) + hpath;
    }
  }

#ifdef HAVE_W32_SYSTEM
  config_path += "\\Application Data\\gnupg\\gpg.conf";
#else
  config_path += "/.gnupg/gpg.conf";
#endif

  return config_path;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value setTempGPGOption(const std::string& option,
///                                  const std::string& value)
///
/// @brief  Creates a backup of the gpg.conf file and writes the options to
///         gpg.conf; This should be called prior to initializing the context.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::setTempGPGOption(
    const std::string& option,
    const std::string& value=NULL
) {

  std::string result;
  std::string config_path = getGPGConfigFilename();
  std::string tmp_config_path = config_path + "-webpg.save";

  std::string gpgconfigfile = LoadFileAsString(config_path);

  if (gpgconfigfile.length()) {
    // Test if we already made a backup, if not, make one!
    std::ifstream tmp_config_exists(tmp_config_path.c_str());
    if (!tmp_config_exists) {
      // Backup the current contents
      std::ofstream tmp_file(tmp_config_path.c_str());
      if (!tmp_file)
        return "error opening temp_file";
      tmp_file << gpgconfigfile;
      tmp_file.close();
    }

    // Ensure we are not appending to an existing line
    gpgconfigfile += "\n";
    gpgconfigfile += option;
    if (value.length())
      gpgconfigfile += " " + value;
    gpgconfigfile += "\n";

    std::ofstream gpg_file(config_path.c_str());
    if (!gpg_file)
      return "error writing gpg_file";
    gpg_file << gpgconfigfile;
    gpg_file.close();
  }

  if (gpgconfigfile.length())
    result = "Set ";
  else
    result = "Unable to set ";

  if (value.length())
    result += "'" + option + " = " + value + "' in file: " + config_path;
  else
    result += "'" + option + "' in file: " + config_path;

  return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value restoreGPGConfig()
///
/// @brief  Restores the gpg.conf file from memory or the backup file.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::restoreGPGConfig()
{
  std::string config_path = getGPGConfigFilename();
  std::string tmp_config_path = config_path + "-webpg.save";

  std::string restore_string;
  std::string result = "gpg config restored from memory";

  if (!original_gpg_config.length()) {
    // We don't have the original file in memory, lets restore the backup
    original_gpg_config = LoadFileAsString(tmp_config_path);
    if (!original_gpg_config.length())
      return "error restoring gpg_file from disk";
    result = "gpg config restored from disk.";
  }

  std::ofstream gpg_file(config_path.c_str());

  if (!gpg_file)
    return "error restoring gpg_file from memory";

  gpg_file << original_gpg_config;
  gpg_file.close();

  remove(tmp_config_path.c_str());
  original_gpg_config = "";

  return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSetHomeDir(const std::string& gnupg_path)
///
/// @brief  Sets the GNUPGHOME static variable to the path specified in
///         gnupg_path. This should be called prior to initializing the
///         gpgme context.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSetHomeDir(const std::string& gnupg_path)
{
  GNUPGHOME = gnupg_path;
  return gnupg_path;
}

Json::Value webpg::gpgGetHomeDir()
{
  return GNUPGHOME;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSetBinary(const std::string& gnupg_exec)
///
/// @brief  Sets the GNUPGBIN static variable to the path specified in
///         gnupg_exec. This should be called prior to initializing the
///         gpgme context.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSetBinary(const std::string& gnupg_exec)
{
  GNUPGBIN = gnupg_exec;
  init();
  return GNUPGBIN;
}

Json::Value webpg::gpgGetBinary()
{
  return GNUPGBIN;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSetGPGConf(const std::string& gpgconf_exec)
///
/// @brief  Sets the GPGCONF static variable to the path specified in
///         gpgconf_exec.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSetGPGConf(const std::string& gpgconf_exec)
{
  GPGCONFBIN = gpgconf_exec;
  init();
  return GPGCONFBIN;
}

Json::Value webpg::gpgGetGPGConf()
{
  return GPGCONFBIN;
}


///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value getTemporaryPath()
///
/// @brief  Attempts to determine the system or user temporary path.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::getTemporaryPath()
{
  Json::Value res;
  char *temp_envvar = getenv("TMP");
  if (temp_envvar != NULL)
    res = temp_envvar;
  temp_envvar = getenv("TEMP");
  if (temp_envvar != NULL)
    res = temp_envvar;
  temp_envvar = getenv("TMPDIR");
  if (temp_envvar != NULL)
    res = temp_envvar;
  if (res.empty())
#ifdef HAVE_W32_SYSTEM
    res = "";

  DWORD ret = 0;
  TCHAR buffer[4096]=TEXT("");

  ret = GetLongPathName(res.asString().c_str(), buffer, 4096);

  if (!ret)
    return res;
  else
    return buffer;
#else
    res = "/tmp";
  return res;
#endif
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgEncrypt(const std::string& data,
///                            const Json::Value& enc_to_keyids,
///                            bool sign)
///
/// @brief  Encrypts the data passed in data with the key ids passed in
///         enc_to_keyids and optionally signs the data.
///
/// @param  data    The data to encrypt.
/// @param  enc_to_keyids   A VariantList of key ids to encrypt to (recpients).
/// @param  sign    The data should be also be signed.
///
/// @returns Json::Value response
/*! @verbatim
response {
    "data":"—————BEGIN PGP MESSAGE—————
            Version: GnuPG v1.4.11 (GNU/Linux)

            jA0EAwMC3hG5kEn899BgyWQW6CHxijX8Zw9oe1OAb7zlofpbVLXbvvyKWPKN3mSk
            i244qGDD8ReGbG87/w52pyNFHd8848TS5r5RwVyDaU8uGFg1XeUSyywAg4p5hg+v
            8Ad/SJfwG0WHXfX9HXoWdkQ+sRkl
            =8KTs
            —————END PGP MESSAGE—————",
    "error":false
}
@endverbatim
*/
///////////////////////////////////////////////////////////////////////////////
/*
    This method passes a string to encrypt, a list of keys to encrypt to calls
        webpg.gpgEncrypt. This method returns a string of encrypted data.
*/
/* This method accepts 3 parameters, data, enc_to_keyids
    and sign [optional; default: 0:NULL:false]
    the return value is a string buffer of the result */
Json::Value webpg::gpgEncrypt(
    const std::string& data,
    const Json::Value& enc_to_keyids,
    const boost::optional<bool>& sign,
    const boost::optional<Json::Value>& opt_signers
) {
  /* declare variables */
  Json::Value signers;
  if (opt_signers)
    signers = *opt_signers;
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t in, out;
  gpgme_key_t *key = new gpgme_key_t[enc_to_keyids.size()];
  unsigned int nrecipients;
  Json::Value recipient, recpients, response;
  gpgme_encrypt_result_t enc_result;
  bool unusable_key = false;

  if (sign && sign == true && signers.size() > 0) {
    unsigned int nsigners;
    Json::Value signer;

    gpgme_key_t signing_key;
    for (nsigners=0; nsigners < signers.size(); nsigners++) {
      signer = signers[nsigners];

      err = gpgme_get_key(ctx, signer.asString().c_str(), &signing_key, 0);
      if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, err, __LINE__, __FILE__);

      err = gpgme_signers_add (ctx, signing_key);
      if (err != GPG_ERR_NO_ERROR)
        return get_error_map(__func__, err, __LINE__, __FILE__);

      gpgme_key_unref (signing_key);
    }

    if (nsigners < 1)
      return get_error_map(__func__, GPG_ERR_MISSING_KEY, __LINE__, __FILE__);
  }

  err = gpgme_data_new_from_mem (&in, data.c_str(), data.length(), 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_set_encoding(in, GPGME_DATA_ENCODING_ARMOR);
  if(err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_set_encoding(out, GPGME_DATA_ENCODING_ARMOR);
  if(err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  for (nrecipients=0; nrecipients < enc_to_keyids.size(); nrecipients++) {
    recipient = enc_to_keyids[nrecipients];

    err = gpgme_get_key(ctx,
                        recipient.asString().c_str(),
                        &key[nrecipients], 0);
    if(err != GPG_ERR_NO_ERROR)
      return get_error_map(__func__, err, __LINE__, __FILE__,
                           recipient.asString().c_str());

    // Check if key is unusable/invalid
    unusable_key =
      key[nrecipients]->invalid? true :
      key[nrecipients]->expired? true :
      key[nrecipients]->revoked? true :
      key[nrecipients]->disabled? true : false;

    if (unusable_key) {
      // Somehow an ususable/invalid key has been passed to the method
      std::string keyid = key[nrecipients]->subkeys->fpr;

      err = key[nrecipients]->invalid? GPG_ERR_UNUSABLE_PUBKEY :
      key[nrecipients]->expired? GPG_ERR_KEY_EXPIRED :
      key[nrecipients]->revoked? GPG_ERR_CERT_REVOKED :
      key[nrecipients]->disabled? GPG_ERR_UNUSABLE_PUBKEY :
          GPG_ERR_UNKNOWN_ERRNO;

      return get_error_map(__func__, err, __LINE__, __FILE__, keyid);
    }

  }

  // NULL terminate the key array
  key[enc_to_keyids.size()] = NULL;

  setTempGPGOption("force-mdc", "");

  if (sign && sign == true) {
    if (enc_to_keyids.size() < 1) {
      err = gpgme_op_encrypt_sign (ctx, NULL, GPGME_ENCRYPT_NO_ENCRYPT_TO,
                                   in, out);
    } else {
      err = gpgme_op_encrypt_sign (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST,
                                   in, out);
    }
    if (err != GPG_ERR_NO_ERROR)
      return get_error_map(__func__, err, __LINE__, __FILE__);
  } else {
    if (enc_to_keyids.size() < 1) {
      // Symmetric encrypt
      err = gpgme_op_encrypt (ctx, NULL, GPGME_ENCRYPT_NO_ENCRYPT_TO, in, out);
    } else {
      err = gpgme_op_encrypt (ctx, key, GPGME_ENCRYPT_ALWAYS_TRUST, in, out);
    }
  }

  restoreGPGConfig();

  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  if (enc_to_keyids.size() < 1) {
    // This was a symmetric operation, and gpgme_op_encrypt does not return
    //  an error if the passphrase is incorrect, so we need to check the
    //  returned value for actual substance.
    gpgme_data_seek(out, 0, SEEK_SET);
    char buf[513];
    gpgme_data_read (out, buf, 512);
    int buflen = strlen(buf);
    if (buflen < 52) {
      gpgme_release (ctx);
      gpgme_data_release (in);
      gpgme_data_release (out);
      return get_error_map(__func__, GPG_ERR_BAD_PASSPHRASE, __LINE__,
                           __FILE__);
    }
  }

  enc_result = gpgme_op_encrypt_result (ctx);

  if (enc_result->invalid_recipients)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  size_t out_size = 0;
  std::string out_buf;
  out_buf = gpgme_data_release_and_get_mem (out, &out_size);
  /* strip the size_t data out of the output buffer */
  out_buf = out_buf.substr(0, out_size);
  /* set the output object to NULL since it has already been released */
  out = NULL;

  /* if any of the gpgme objects have not yet
      been release, do so now */
  for (nrecipients=0; nrecipients < enc_to_keyids.size(); nrecipients++)
    gpgme_key_unref(key[nrecipients]);

  if (ctx)
    gpgme_release (ctx);
  if (in)
    gpgme_data_release (in);
  if (out)
    gpgme_data_release (out);

  response["data"] = out_buf;
  response["error"] = false;

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSymmetricEncrypt(const std::string& data, bool sign)
///
/// @brief  Calls webpg::gpgEncrypt() without any recipients specified
///         which initiates a Symmetric encryption method on the gpgme context.
///
/// @param  data    The data to symmetrically encrypt.
/// @param  sign    The data should also be signed. NOTE: Signed symmetric
///                 encryption does not work in gpgme v1.3.2; For details,
///                 see https://bugs.g10code.com/gnupg/issue1440
///////////////////////////////////////////////////////////////////////////////
/*
  This method just calls webpg.gpgEncrypt without any keys
    as the parameter, which then uses Symmetric Encryption.
*/
/* This method accepts 2 parameters, data and sign [optional;
    default: 0:NULL:false].
    the return value is a string buffer of the result */
Json::Value webpg::gpgSymmetricEncrypt(
    const std::string& data,
    const boost::optional<bool>& sign,
    const boost::optional<Json::Value>& opt_signers
) {
  Json::Value empty_keys;
  return webpg::gpgEncrypt(data, empty_keys, sign, opt_signers);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgDecryptVerify(const std::string& data,
///                                  const std::string& plaintext,
///                                  int use_agent)
///
/// @brief  Attempts to decrypt and verify the string data. If use_agent
///         is 0, it will attempt to disable the key-agent to prevent the
///         passphrase dialog from displaying. This is useful in cases where
///         you want to verify or decrypt without unlocking the private keyring
///         (i.e. in an automated parsing environment).
///
/// @param  data    The data to decrypt and/or verify.
/// @param  use_agent   Attempt to disable the gpg-agent
/// @param  plaintext   The plaintext of a detached signature.
///
/// @returns Json::Value response
/*! @verbatim
response {
  "data":"This is a test of symmetric encrypted data with a signature...\n",
  "error":false,
  "message_type":"signed_message",
  "signatures":{
    "0":{
      "expiration":"0",
      "fingerprint":"0C178DD984F837340075BD76C599711F5E82BB93",
      "status":"GOOD",
      "timestamp":"1346645718",
      "validity":"full"
    }
  }
}
@endverbatim
*/
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgDecryptVerify(
    const std::string& data,
    const std::string& plaintext,
    int use_agent
) {
  gpgme_ctx_t ctx;
  gpgme_error_t err;
  gpgme_decrypt_result_t decrypt_result;
  gpgme_verify_result_t verify_result;
  gpgme_signature_t sig;
  gpgme_sig_notation_t notation;
  gpgme_data_t in, out, plain;
  std::string out_buf;
  std::string envvar;
  Json::Value response;
  int nsig = 0, nnotations, ret;
  int tnsig = 0;
  char buf[513];
#ifndef HAVE_W32_SYSTEM
#ifndef FB_MACOSX
    char *agent_info = getenv("GPG_AGENT_INFO");
#endif
#endif

  if (use_agent == 0) {
    // Set the GPG_AGENT_INFO to null because the user shouldn't be bothered
    //  for a passphrase if we get a chunk of encrypted data by mistake.
    setTempGPGOption("batch", "");
    // Set the defined password to be "", if anything else is sent to the
    //  agent, this will result in a return error of invalid key when
    //  performing Symmetric decryption (because the passphrase is the
    //  secret key)
    setTempGPGOption("passphrase", "\"\"");
#ifndef HAVE_W32_SYSTEM
#ifndef FB_MACOSX
    // Poison the GPG_AGENT_INFO environment variable
    envvar = "GPG_AGENT_INFO=INVALID";
    putenv(strdup(envvar.c_str()));
#endif
#endif
    // Create our context with the above modifications
    ctx = get_gpgme_ctx();
    // Set the passphrase callback to just send "\n", which will
    //  deal with the case there is no gpg-agent
    gpgme_set_passphrase_cb (ctx, passphrase_cb, NULL);
  } else {
    ctx = get_gpgme_ctx();
  }

  err = gpgme_data_new_from_mem (&in, data.c_str(), data.length(), 0);
  if (err != GPG_ERR_NO_ERROR) {
    return get_error_map(__func__, err, __LINE__, __FILE__);
  }

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR) {
    return get_error_map(__func__, err, __LINE__, __FILE__);
  }

  if (plaintext.length() > 0) {
    err = gpgme_data_new_from_mem (&plain, plaintext.c_str(),
                                   plaintext.length(), 0);
    if (err != GPG_ERR_NO_ERROR) {
      return get_error_map(__func__, err, __LINE__, __FILE__);
    }
    gpgme_data_seek (plain, 0, SEEK_SET);
    gpgme_data_seek (in, 0, SEEK_SET);
    err = gpgme_op_verify (ctx, in, plain, NULL);
  } else {
    err = gpgme_op_decrypt_verify (ctx, in, out);
  }

  decrypt_result = gpgme_op_decrypt_result (ctx);
  verify_result = gpgme_op_verify_result (ctx);

  if (decrypt_result && decrypt_result->file_name
      && strlen(decrypt_result->file_name) > 4)
    response["filename"] = (char *) decrypt_result->file_name;

  if (use_agent == 0) {
    // Restore the gpg.conf options
    restoreGPGConfig();
    // Restore GPG_AGENT_INFO to its original value
#ifndef HAVE_W32_SYSTEM
#ifndef FB_MACOSX
    if (agent_info != NULL) {
      envvar = "GPG_AGENT_INFO=";
      envvar += agent_info;
      putenv(strdup(envvar.c_str()));
    }
#endif
#endif
  }

  if (err != GPG_ERR_NO_ERROR && !verify_result) {
    // There was an error returned while verifying;
    //   either bad data, or signed only data
    if (verify_result && verify_result->signatures) {
      if (verify_result->signatures->status != GPG_ERR_NO_ERROR) {
        // No valid GPG data to decrypt or signatures to verify;
        //  possibly bad armor.
        return get_error_map(__func__, err, __LINE__, __FILE__);
      }
    }
    if (gpg_err_code(err) == GPG_ERR_CANCELED) {
      return get_error_map(__func__, err, __LINE__, __FILE__);
    }
    if (gpg_err_code(err) == GPG_ERR_BAD_PASSPHRASE) {
      return get_error_map(__func__, err, __LINE__, __FILE__);
    }
    if (gpg_err_source(err) == GPG_ERR_SOURCE_PINENTRY) {
      return get_error_map(__func__, err, __LINE__, __FILE__);
    }
    if (gpg_err_source(err) == GPG_ERR_SOURCE_GPGAGENT) {
      return get_error_map(__func__, err, __LINE__, __FILE__);
    }
  }

  Json::Value signatures;
  if (verify_result && verify_result->signatures) {
    tnsig = 0;
    for (nsig=0, sig=verify_result->signatures; sig; sig = sig->next, nsig++) {
      Json::Value signature, notations_map;
      signature["fingerprint"] = nonnull (sig->fpr);
      signature["timestamp"] = i_to_str(sig->timestamp);
      signature["expiration"] = i_to_str(sig->exp_timestamp);
      signature["validity"] =
        sig->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
        sig->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
        sig->validity == GPGME_VALIDITY_NEVER? "never":
        sig->validity == GPGME_VALIDITY_MARGINAL? "marginal":
        sig->validity == GPGME_VALIDITY_FULL? "full":
        sig->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";
      signature["validity_reason"] = gpgme_strerror(sig->validity_reason);
      signature["status"] =
        gpg_err_code (sig->status) == GPG_ERR_NO_ERROR? "GOOD":
        gpg_err_code (sig->status) == GPG_ERR_BAD_SIGNATURE? "BAD_SIG":
        gpg_err_code (sig->status) == GPG_ERR_NO_PUBKEY? "NO_PUBKEY":
        gpg_err_code (sig->status) == GPG_ERR_NO_DATA? "NO_SIGNATURE":
        gpg_err_code (sig->status) == GPG_ERR_SIG_EXPIRED? "GOOD_EXPSIG":
        gpg_err_code (sig->status) == GPG_ERR_KEY_EXPIRED? "GOOD_EXPKEY":
        "INVALID";
      signature["pubkey_algo"] = sig->pubkey_algo;
      signature["pubkey_algo_name"] = (sig->pubkey_algo) ?
                                      gpgme_pubkey_algo_name(sig->pubkey_algo):
                                      "[?]";
      signature["hash_algo"] = sig->hash_algo;
      signature["hash_algo_name"] = (sig->hash_algo) ?
                                    gpgme_hash_algo_name(sig->hash_algo):
                                    "[?]";
      signature["pka_address"] = (sig->pka_address) ? sig->pka_address : "";
      signature["pka_trust"] = i_to_str (sig->pka_trust);
      signature["chain_model"] = i_to_str (sig->chain_model);
      Json::Value notation_map;
      for (nnotations=0, notation=sig->notations; notation;
           notation = notation->next, nnotations++) {
          notation_map["name"] = nonnull (notation->name);
          notation_map["name_len"] = notation->name_len;
          notation_map["value"] = nonnull (notation->value);
          notation_map["value_len"] = notation->value_len;
          notations_map[i_to_str(nnotations)] = notation_map;
      }
      signature["notations"] = notations_map;
      signatures[i_to_str(nsig)] = signature;
      tnsig++;
    }
  }

  if (nsig < 1 || err == 11) {
    response["message_type"] = "encrypted_message";
    if (use_agent == 0) {
        response["message_event"] = "auto";
    } else {
        response["message_event"] = "manual";
    }
  } else {
    response["message_type"] = "signed_message";
  }

  if (err != GPG_ERR_NO_ERROR && tnsig < 1)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  if (gpgme_err_code (err) == 58 && tnsig < 1) {
    gpgme_data_release (out);
    response["data"] = data;
    response["message_type"] = "detached_signature";
  } else {
    ret = gpgme_data_seek(out, 0, SEEK_SET);

    if (ret)
      return get_error_map(__func__, err, __LINE__, __FILE__);

    while ((ret = gpgme_data_read (out, buf, 512)) > 0)
      out_buf += buf;

    if (ret < 0)
      return get_error_map(__func__, err, __LINE__, __FILE__);

    if (out_buf.length() < 1) {
      response["data"] = data;
      response["message_type"] = "detached_signature";
      gpgme_data_release (out);
    } else {
      size_t out_size = 0;
      gpgme_data_seek(out, 0, SEEK_SET);
      out_buf = gpgme_data_release_and_get_mem (out, &out_size);

      /* strip the size_t data out of the output buffer */
      out_buf = out_buf.substr(0, out_size);
      response["data"] = out_buf;
    }
  }

  response["signatures"] = signatures;
  response["error"] = false;
  gpgme_data_release (in);
  gpgme_release (ctx);

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgDecrypt(const std::string& data)
///
/// @brief  Calls webpg::gpgDecryptVerify() with the use_agent flag
///         specifying to not disable the gpg-agent.
///
/// @param  data    The data to decyrpt.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgDecrypt(const std::string& data)
{
  return webpg::gpgDecryptVerify(data, "", 1);
}

Json::Value webpg::gpgVerify(
    const std::string& data,
    const boost::optional<std::string>& plaintext
) {
  if (plaintext)
    return webpg::gpgDecryptVerify(data, *plaintext, 0);
  else
    return webpg::gpgDecryptVerify(data, "", 0);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSignText(const std::string& plain_text,
///                             Json::Value& signers, int sign_mode)
///
/// @brief  Signs the text specified in plain_text with the key ids specified
///         in signers, with the signature mode specified in sign_mode.
///
/// @param  signers    The key ids to sign with.
/// @param  plain_text    The data to sign.
/// @param  sign_mode   The GPGME_SIG_MODE to use for signing.
///
/// @returns Json::Value response
/*! @verbatim
response {
  "data":"—————BEGIN PGP SIGNED MESSAGE—————
          Hash: SHA1

          This is some text to sign...
          —————BEGIN PGP SIGNATURE—————
          Version: GnuPG v1.4.11 (GNU/Linux)

          iQEcBAEBAgAGBQJQTQWwAAoJEMWZcR9egruTsp8H/A/qNCyzSsoVR+VeQQTEBcfi
          OpJkwQ5BCm2/5ZdlFATijaHe3s1C2OYUmncb3Z+OIIy8FNzCuMboNl83m5ro0Ng8
          IgSAcVJpLlVwbkAfGyWqmQ48yS7gDqb0pUSgkhEgCnMn+yDtFWPgAVTiKpuWJpf8
          NiIO1cNm+3RwSnftSxGDLTUu3UoXh7BZXnoOMa63fUukF3duzIrIUhav8zg/Vfrb
          JK7tC2UPRGJCVREr/2EEYvpasHxHX2yJpT+cYM1ChCGgo+Kd3OX4sDRAALZ+7Gwm
          NdrvT57QxQ7Y/cSd5H+c3/vpYzSwwmXmK+/m3uVUHIdccOvGNg7vNg8aYSfR1FY=
          =v9Ab
          —————END PGP SIGNATURE—————",
  "error":false
}
@endverbatim
*/
///////////////////////////////////////////////////////////////////////////////
/*
  sign_mode is one of:
    0: GPGME_SIG_MODE_NORMAL
    1: GPGME_SIG_MODE_DETACH
    2: GPGME_SIG_MODE_CLEAR
*/
Json::Value webpg::gpgSignText(
    const std::string& plain_text,
    const Json::Value& signers,
    const boost::optional<int>& opt_sign_mode
) {
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t in, out;
  gpgme_key_t key;
  gpgme_new_signature_t sig;
  gpgme_sig_mode_t sig_mode;
  gpgme_sign_result_t sign_result;
  unsigned int nsigners;
  int sign_mode = 2, nsig;
  Json::Value signer;
  Json::Value result;

  if (opt_sign_mode)
    sign_mode = *opt_sign_mode;

  if (sign_mode == 0) {
    sig_mode = GPGME_SIG_MODE_NORMAL;
    gpgme_set_armor (ctx, 0);
  } else if (sign_mode == 1) {
    sig_mode = GPGME_SIG_MODE_DETACH;
  } else {
    sig_mode = GPGME_SIG_MODE_CLEAR;
  }

  for (nsigners=0; nsigners < signers.size(); nsigners++) {
    signer = signers[nsigners];

    err = gpgme_get_key(ctx, signer.asString().c_str(), &key, 0);
    if (err != GPG_ERR_NO_ERROR)
      return get_error_map(__func__, err, __LINE__, __FILE__);

    err = gpgme_signers_add (ctx, key);
    if (err != GPG_ERR_NO_ERROR)
      return get_error_map(__func__, err, __LINE__, __FILE__);

    gpgme_key_unref (key);
  }

  if (nsigners < 1)
    return get_error_map(__func__, GPG_ERR_MISSING_KEY, __LINE__, __FILE__);

  err = gpgme_data_new_from_mem (&in, plain_text.c_str(),
                                 plain_text.length(), 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_op_sign(ctx, in, out, sig_mode);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  sign_result = gpgme_op_sign_result (ctx);

  if (!sign_result)
    return get_error_map(__func__, GPG_ERR_NO_DATA, __LINE__, __FILE__);

  gpgme_data_seek(out, 0, SEEK_SET);

  size_t out_size = 0;
  std::string out_buf;
  out_buf = gpgme_data_release_and_get_mem (out, &out_size);
  /* strip the size_t data out of the output buffer */
  out_buf = out_buf.substr(0, out_size);
  /* set the output object to NULL since it has
      already been released */
  out = NULL;

  result["error"] = false;
  result["data"] = out_buf;

  Json::Value signatures_map;
  for (nsig=0, sig=sign_result->signatures; sig; sig = sig->next, nsig++) {
    Json::Value  signature_map;
    signature_map["pubkey_algo"] = sig->pubkey_algo;
    signature_map["pubkey_algo_name"] =
                          gpgme_pubkey_algo_name(sig->pubkey_algo);
    signature_map["hash_algo"] = sig->hash_algo;
    signature_map["hash_algo_name"] =
                          gpgme_hash_algo_name(sig->hash_algo);
    signature_map["timestamp"] = i_to_str(sig->timestamp);
    signature_map["fingerprint"] = sig->fpr;
    signatures_map[i_to_str(nsig)] = signature_map;
  }
  result["signatures"] = signatures_map;

  gpgme_data_release (in);
  gpgme_release (ctx);

  return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSignUID(const std::string& keyid, long sign_uid,
///                            const std::string& with_keyid, long local_only,
///                            long trust_sign, long trust_level)
///
/// @brief  Signs the UID index of the specified keyid using the signing key
///         with_keyid.
///
/// @param  keyid    The ID of the key with the desired UID to sign.
/// @param  sign_uid    The 0 based index of the UID.
/// @param  with_keyid  The ID of the key to create the signature with.
/// @param  local_only  Specifies if the signature is non-exportable.
/// @param  trust_sign  Specifies if this is a trust signature.
/// @param  trust_level The level of trust to assign.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSignUID(
    const std::string& keyid,
    long sign_uid,
    const std::string& with_keyid,
    long local_only,
    long trust_sign,
    long trust_level,
    const boost::optional<std::string>& opt_notation_name=NULL,
    const boost::optional<std::string>& opt_notation_value=NULL
) {
  std::string notation_name, notation_value;
  if (opt_notation_name)
    notation_name = *opt_notation_name;
  if (opt_notation_value)
    notation_value = *opt_notation_value;
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value result;
  current_uid = i_to_str(sign_uid);

  /* set the default key to the with_keyid
      gpgSetPreference returns the original value (if any) of
      the 'default-key' configuration parameter. We will put
      this into a variable so we can restore the setting when
      our UID Signing operation is complete (or failed)
  */

  /* collect the original value so we can restore when done */
  std::string original_value = get_preference("default-key");
  webpg::gpgSetPreference("default-key", (char *) with_keyid.c_str());

  /* Release the context and create it again to catch the changes */
  gpgme_release (ctx);
  ctx = get_gpgme_ctx();

  if (notation_name.length() > 0 && notation_value.length() > 0) {
    err = gpgme_sig_notation_add (ctx, notation_name.c_str(),
                                  notation_value.c_str(),
                                  GPGME_SIG_NOTATION_HUMAN_READABLE);
    if (err != GPG_ERR_NO_ERROR)
      result = get_error_map(__func__, err, __LINE__, __FILE__);
  }

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    result = get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    result = get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgSignUID(keyid='" + keyid + "', sign_uid='" +
                  i_to_str(sign_uid) + "', with_keyid='" + with_keyid +
                  "', local_only='" + i_to_str(local_only) +
                  "', trust_sign='" + i_to_str(trust_sign) +
                  "', trust_level='" + i_to_str(trust_level) + "');\n";

  current_edit = WEBPG_EDIT_SIGN;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);

  // FIXME: The get_error_map method returns GPG_ERR_* values, but in this
  //        operation, err is a GPGME_STATUS_* code... The error_map will be
  //        woefully misleading.
  if (err != GPG_ERR_NO_ERROR)
    result = get_error_map(__func__, err, __LINE__, __FILE__);

  /* if the original value was not empty, reset it to the previous value */
  if (strcmp ((char *) original_value.c_str(), "0"))
    webpg::gpgSetPreference("default-key", original_value);

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  if (result.size())
      return result;

  result["error"] = false;
  result["result"] = "UID signed";

  return result;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgEnableKey(const std::string& keyid)
///
/// @brief  Sets the key specified with keyid as enabled in gpupg.
///
/// @param  keyid    The ID of the key to enable.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgEnableKey(const std::string& keyid)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgEnableKey(keyid='" + keyid + "');\n";
  current_edit = WEBPG_EDIT_ENABLE;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  size_t out_size = 0;
  std::string out_buf;
  out_buf = gpgme_data_release_and_get_mem (out, &out_size);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["result"] = "key enabled";
  response["out"] = out_buf;

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgDisableKey(const std::string& keyid)
///
/// @brief  Sets the key specified with keyid as disabled in gpupg.
///
/// @param  keyid    The ID of the key to disable.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgDisableKey(const std::string& keyid)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgDisableKey(keyid='" + keyid + "');\n";
  current_edit = WEBPG_EDIT_DISABLE;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["result"] = "key disabled";

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgDeleteUIDSign(const std::string& keyid,
///                                  long uid,
///                                  long signature)
///
/// @brief  Deletes the Signature signature on the uid of keyid.
///
/// @param  keyid   The keyid containing the UID to delete signature from.
/// @param  uid    The index of the UID containing the signature to delete.
/// @param  signature   The signature index of the signature to delete.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgDeleteUIDSign(
    const std::string& keyid,
    long uid,
    long signature
) {
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;

  current_uid = i_to_str(uid);
  current_sig = i_to_str(signature);

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgDeleteUIDSign(keyid='" + keyid + "', uid='" +
      i_to_str(uid) + "', signature='" + i_to_str(signature) + "');\n";
  current_edit = WEBPG_EDIT_DELSIGN;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  current_uid = "0";
  current_sig = "0";

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["result"] = "signature deleted";

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn void genkey_progress_cb(void *self,
///                      const char *what,
///                      int type,
///                      int current,
///                      int total)
///
/// @brief  Called by the long-running, asymmetric gpg genkey method to display
///         the status.
///
/// @param  self    A reference to webpg, since the method is called
///                 outside of the class.
/// @param  what    The current action status from gpg genkey.
/// @param  type    The type of of action.
/// @param  current ?
/// @param  total   ?
///////////////////////////////////////////////////////////////////////////////
void webpg::genkey_progress_cb(
    void *self,
    const char *what,
    int type,
    int current,
    int total
) {
  if (!strcmp (what, "primegen") && !current && !total
      && (type == '.' || type == '+' || type == '!'
      || type == '^' || type == '<' || type == '>')) {
      g_callback("onkeygenprogress", i_to_str(type).c_str());
  }
  if (!strcmp (what, "complete")) {
      g_callback("onkeygencomplete", "complete");
  }
}

void webpg::status_progress_cb(
    void *self,
    const char* msg
) {
  s_callback("onstatusprogress", msg);
}

Json::Value webpg::getKeyCount() {
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_key_t key;
  Json::Value keycount;
  gpgme_keylist_result_t result;

  unsigned int pubKeyCount = 0,
               priKeyCount = 0;

  /* set protocol to use in our context */
  err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
  if(err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_set_keylist_mode (ctx,
    GPGME_KEYLIST_MODE_LOCAL &
    ~GPGME_KEYLIST_MODE_SIGS &
    ~GPGME_KEYLIST_MODE_SIG_NOTATIONS
  );

  if(err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_op_keylist_start (ctx, NULL, 0);

  if(err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  while (!(err = gpgme_op_keylist_next (ctx, &key))) {
    pubKeyCount++;
    gpgme_key_unref (key);
  }

  err = gpgme_op_keylist_end (ctx);

  if(err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_op_keylist_start (ctx, NULL, 1);

  if(err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  while (!(err = gpgme_op_keylist_next (ctx, &key))) {
    priKeyCount++;
    gpgme_key_unref (key);
  }

  if (gpg_err_code (err) != GPG_ERR_EOF)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  result = gpgme_op_keylist_result (ctx);

  if (result->truncated)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_release (ctx);

  keycount["public_keys"] = pubKeyCount;
  keycount["private_keys"] = priKeyCount;
  keycount["total"] = pubKeyCount + priKeyCount;

  return keycount;
}

Json::Value webpg::getKeyListWorker(
    const std::string& name,
    bool secret_only,
    bool fast,
    void* APIObj,
    void(*cb_status)(
      void *self,
      const char *msg
    )
) {
  /* declare variables */
  bool return_list = false;
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_key_t key;
  gpgme_keylist_result_t result;
  gpgme_user_id_t uid;
  gpgme_key_sig_t sig;
  gpgme_sig_notation_t notation;
  gpgme_subkey_t subkey;
  Json::Value keylist_map(Json::objectValue);
  Json::Value uid_map(Json::objectValue);
  Json::FastWriter writer;

  /* set protocol to use in our context */
  err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
  if(err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  /* determine if we are in fast-list mode - we don't want signatures or
      notations in fast-list mode */
  if (fast || fast == true || fast == 1) {
    /* apply the keylist mode to the context */
    gpgme_set_keylist_mode (ctx,
      (gpgme_get_keylist_mode (ctx) |
      (GPGME_KEYLIST_MODE_LOCAL &
      ~GPGME_KEYLIST_MODE_SIGS &
      ~GPGME_KEYLIST_MODE_SIG_NOTATIONS))
    );
  } else {
    /* apply the keylist mode to the context
        NOTE: The keylist mode flag GPGME_KEYLIST_MODE_SIGS
            returns the signatures of UIDS with the key */
    gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx)
                                | GPGME_KEYLIST_MODE_LOCAL
                                | GPGME_KEYLIST_MODE_SIGS
                                | GPGME_KEYLIST_MODE_SIG_NOTATIONS));
  }

  if (EXTERNAL == 1) {
    err = gpgme_set_keylist_mode (ctx, GPGME_KEYLIST_MODE_EXTERN);
    EXTERNAL = 0;
    return_list = true;
  }

  if (name.length() > 0) { // limit key listing to search criteria 'name'
    err = gpgme_op_keylist_start (ctx, name.c_str(), secret_only);
  } else { // list all keys
    err = gpgme_op_keylist_start (ctx, NULL, secret_only);
  }

  if(err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  while (!(err = gpgme_op_keylist_next (ctx, &key))) {
    /*declare nuids (Number of UIDs)
        and nsig (Number of signatures)
        and nsub (Number of Subkeys)*/
    int nuids, nsig, nsub, nnotations;
    Json::Value key_map(Json::objectValue);

    /* if secret keys are being returned, re-retrieve the key so we get all of
       the key informoation */
    if(secret_only == true && key->subkeys && key->subkeys->keyid)
        err = gpgme_get_key (ctx, key->subkeys->keyid, &key, 0);

    /* iterate through the keys/subkeys and add them to the key_map object */
    if (key->uids && key->uids->name)
        key_map["name"] = nonnull (key->uids->name);
    if (key->subkeys && key->subkeys->keyid)
        key_map["id"] = nonnull (key->subkeys->keyid);
    if (key->subkeys && key->subkeys->fpr)
        key_map["fingerprint"] = nonnull (key->subkeys->fpr);
    if (key->uids && key->uids->email)
        key_map["email"] = nonnull (key->uids->email);
    key_map["expired"] = key->expired? true : false;
    key_map["revoked"] = key->revoked? true : false;
    key_map["disabled"] = key->disabled? true : false;
    key_map["invalid"] = key->invalid? true : false;
    key_map["secret"] = (secret_only)? true : false;
    key_map["protocol"] =
        key->protocol == GPGME_PROTOCOL_OpenPGP? "OpenPGP":
        key->protocol == GPGME_PROTOCOL_CMS? "CMS":
        key->protocol == GPGME_PROTOCOL_UNKNOWN? "Unknown": "[?]";
    key_map["can_encrypt"] = key->can_encrypt? true : false;
    key_map["can_sign"] = key->can_sign? true : false;
    key_map["can_certify"] = key->can_certify? true : false;
    key_map["can_authenticate"] = key->can_authenticate? true : false;
    key_map["is_qualified"] = key->is_qualified? true : false;
    key_map["owner_trust"] =
        key->owner_trust == GPGME_VALIDITY_UNKNOWN? "unknown":
        key->owner_trust == GPGME_VALIDITY_UNDEFINED? "undefined":
        key->owner_trust == GPGME_VALIDITY_NEVER? "never":
        key->owner_trust == GPGME_VALIDITY_MARGINAL? "marginal":
        key->owner_trust == GPGME_VALIDITY_FULL? "full":
        key->owner_trust == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";

    Json::Value subkeys_map(Json::objectValue);
    for (nsub=0, subkey=key->subkeys; subkey; subkey = subkey->next, nsub++){
        Json::Value subkey_item_map(Json::objectValue);
        subkey_item_map["subkey"] = nonnull (subkey->fpr);
        subkey_item_map["expired"] = subkey->expired? true : false;
        subkey_item_map["revoked"] = subkey->revoked? true : false;
        subkey_item_map["disabled"] = subkey->disabled? true : false;
        subkey_item_map["invalid"] = subkey->invalid? true : false;
        subkey_item_map["secret"] = subkey->secret? true : false;
        subkey_item_map["can_encrypt"] = subkey->can_encrypt? true : false;
        subkey_item_map["can_sign"] = subkey->can_sign? true : false;
        subkey_item_map["can_certify"] = subkey->can_certify? true : false;
        subkey_item_map["can_authenticate"] =
                          subkey->can_authenticate? true : false;
        subkey_item_map["is_qualified"] = subkey->is_qualified? true : false;
        subkey_item_map["algorithm"] = subkey->pubkey_algo;
        subkey_item_map["algorithm_name"] =
                          nonnull(gpgme_pubkey_algo_name(subkey->pubkey_algo));
        subkey_item_map["size"] = subkey->length;
        subkey_item_map["created"] = i_to_str(subkey->timestamp);
        subkey_item_map["expires"] = i_to_str(subkey->expires);
        subkeys_map[i_to_str(nsub)] = subkey_item_map;
    }

    key_map["subkeys"] = subkeys_map;

    Json::Value uids_map(Json::objectValue);
    for (nuids=0, uid=key->uids; uid; uid = uid->next, nuids++) {
      Json::Value uid_item_map(Json::objectValue);
      uid_item_map["uid"] = nonnull (uid->name);
      uid_item_map["email"] = nonnull (uid->email);
      uid_item_map["comment"] = nonnull (uid->comment);
      uid_item_map["invalid"] = uid->invalid? true : false;
      uid_item_map["revoked"] = uid->revoked? true : false;

      Json::Value signatures_map(Json::objectValue);

      for (nsig=0, sig=uid->signatures; sig; sig = sig->next, nsig++) {
        Json::Value signature_map(Json::objectValue);
        Json::Value notations_map(Json::objectValue);
        signature_map["keyid"] = nonnull (sig->keyid);
        signature_map["algorithm"] = sig->pubkey_algo;
        signature_map["algorithm_name"] =
                          nonnull(gpgme_pubkey_algo_name(sig->pubkey_algo));
        signature_map["revoked"] = sig->revoked? true : false;
        signature_map["expired"] = sig->expired? true : false;
        signature_map["invalid"] = sig->invalid? true : false;
        signature_map["exportable"] = sig->exportable? true : false;
        signature_map["created"] = i_to_str(sig->timestamp);
        signature_map["expires"] = i_to_str(sig->expires);
        signature_map["uid"] = nonnull (sig->uid);
        signature_map["name"] = nonnull (sig->name);
        signature_map["comment"] = nonnull (sig->comment);
        signature_map["email"] = nonnull (sig->email);
        Json::Value notation_map;
        for (nnotations=0, notation=sig->notations; notation;
             notation = notation->next, nnotations++) {
            notation_map["name"] = nonnull (notation->name);
            notation_map["name_len"] = notation->name_len;
            notation_map["value"] = nonnull (notation->value);
            notation_map["value_len"] = notation->value_len;
            notations_map[i_to_str(nnotations)] = notation_map;
        }
        notations_map["notation_count"] = nnotations;
        signature_map["notations"] = notations_map;
        signatures_map[i_to_str(nsig)] = signature_map;
      }
      uid_item_map["signatures_count"] = nsig;
      uid_item_map["signatures"] = signatures_map;
      uid_item_map["validity"] =
        uid->validity == GPGME_VALIDITY_UNKNOWN? "unknown":
        uid->validity == GPGME_VALIDITY_UNDEFINED? "undefined":
        uid->validity == GPGME_VALIDITY_NEVER? "never":
        uid->validity == GPGME_VALIDITY_MARGINAL? "marginal":
        uid->validity == GPGME_VALIDITY_FULL? "full":
        uid->validity == GPGME_VALIDITY_ULTIMATE? "ultimate": "[?]";
      uids_map[i_to_str(nuids)] = uid_item_map;
    }
    key_map["uids"] = uids_map;
    key_map["nuids"] = nuids;

    if (cb_status != NULL) {
      cb_status(APIObj, writer.write(key_map).c_str());
    } else if (return_list == false && name.length() > 0)
      keylist_map = key_map;
    else
      keylist_map[key->subkeys->keyid] = key_map;

    gpgme_key_unref (key);
  }

  if (gpg_err_code (err) != GPG_ERR_EOF) {
    if (cb_status != NULL)
      cb_status(
        APIObj,
        writer.write(
          get_error_map(__func__, err, __LINE__, __FILE__)
        ).c_str()
      );
    else
      return get_error_map(__func__, err, __LINE__, __FILE__);
  }

  err = gpgme_op_keylist_end (ctx);

  if(err != GPG_ERR_NO_ERROR) {
    if (cb_status != NULL)
      cb_status(
        APIObj,
        writer.write(
          get_error_map(__func__, err, __LINE__, __FILE__)
        ).c_str()
      );
    else
      return get_error_map(__func__, err, __LINE__, __FILE__);
  }

  result = gpgme_op_keylist_result (ctx);

  if (result->truncated) {
    if (cb_status != NULL)
      cb_status(
        APIObj,
        writer.write(
          get_error_map(__func__, err, __LINE__, __FILE__)
        ).c_str()
      );
    else
      return get_error_map(__func__, err, __LINE__, __FILE__);
  }

  gpgme_release (ctx);

  if (cb_status != NULL) {
    cb_status(APIObj, "{\"status\": \"complete\"}");
    return "";
  }

  return keylist_map;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn std::string webpg::gpgGenKeyWorker(genKeyParams parmas,
///                                        void* APIObj,
///                                        void(*cb_status)(
///                                          void *self,
///                                          const char *what,
///                                          int type,
///                                          int current,
///                                          int total
///                                        )
///                        )
///
/// @brief  Creates a threaded worker to run the gpg keygen operation.
///
/// @param  key_type    The key type to genereate.
/// @param  key_length    The size of the key to generate.
/// @param  subkey_type   The subkey type to generate.
/// @param  subkey_length   The size of the subkey to genereate.
/// @param  name_real   The name to assign the UID.
/// @param  name_comment    The comment to assign to the UID.
/// @param  name_email  The email address to assign to the UID.
/// @param  expire_date The expiration date to assign to the generated key.
/// @param  passphrase  The passphrase to assign the to the key.
/// @param  APIObj  A reference to webpg.
/// @param  cb_status   The progress callback for the operation.
///////////////////////////////////////////////////////////////////////////////
// FIXME: This method should return Json::Value object value, not a string
std::string webpg::gpgGenKeyWorker(genKeyParams& params, void* APIObj,
     void(*cb_status)(
      void *self,
      const char *what,
      int type,
      int current,
      int total)
    )
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  std::string params_str = "<GnupgKeyParms format=\"internal\">\n"
    "Key-Type: " + params.key_type + "\n"
    "Key-Length: " + params.key_length + "\n"
    "Subkey-Type: " + params.subkey_type + "\n"
    "Subkey-Length: " + params.subkey_length + "\n"
    "Name-Real: " + params.name_real + "\n";
  if (params.name_comment.length() > 0) {
    params_str += "Name-Comment: " + params.name_comment + "\n";
  }
  if (params.name_email.length() > 0) {
    params_str += "Name-Email: " + params.name_email + "\n";
  }
  if (params.expire_date.length() > 0) {
    params_str += "Expire-Date: " + params.expire_date + "\n";
  } else {
    params_str += "Expire-Date: 0\n";
  }
  if (params.passphrase.length() > 0) {
    params_str += "Passphrase: " + params.passphrase + "\n";
  }
  params_str += "</GnupgKeyParms>\n";

  gpgme_genkey_result_t result;

  gpgme_set_progress_cb (ctx, cb_status, APIObj);

  edit_status = "gpgGenKeyWorker(key_type='" + params.key_type +
      "', key_length='" + params.key_length + "', subkey_type='" +
      params.subkey_type + "', subkey_length='" + params.subkey_length +
      "', name_real='" + params.name_real + "', name_comment='" +
      params.name_comment + "', name_email='" + params.name_email +
      "', expire_date='" + params.expire_date + "');\n";

  err = gpgme_op_genkey (ctx, (char *) params_str.c_str(), NULL, NULL);
  if (err)
    return get_error_map(__func__, err, __LINE__, __FILE__).toStyledString();

  result = gpgme_op_genkey_result (ctx);

  if (!result)
    return "error with result";

  std::string msg = result->fpr ? result->fpr : "none";
  msg += " (";
  msg += result->primary ? (result->sub ? "primary, sub" : "primary")
    : (result->sub ? "sub" : "none");
  msg += ")";

  gpgme_release (ctx);
  const char* status = (char *) "complete";
  cb_status(APIObj, status, 33, 33, 33);
  return "done";
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgGenSubKeyWorker(genSubKeyParams params,
///                                    void* APIObj,
///                                    void(*cb_status)(
///                                      void *self,
///                                      const char *what,
///                                      int type,
///                                      int current,
///                                      int total
///                                    )
///                 )
///
/// @brief  Creates a threaded worker to run the gpg keygen operation.
///
/// @param  keyid   The ID of the key to create the subkey on.
/// @param  subkey_type    The subkey type to genereate.
/// @param  subkey_length    The size of the subkey to generate.
/// @param  subkey_expire The expiration date to assign to the generated key.
/// @param  sign_flag  Set the sign capabilities flag.
/// @param  enc_flag    Set the encrypt capabilities flag.
/// @param  auth_flag   Set the auth capabilities flag.
/// @param  APIObj  A reference to webpg.
/// @param  cb_status   The progress callback for the operation.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgGenSubKeyWorker(genSubKeyParams params,
    void* APIObj,
    void(*cb_status)(
      void *self,
      const char *what,
      int type,
      int current,
      int total
    )
) {
  // Set the option expert so we can access all of the subkey types
  setTempGPGOption("expert", "");

  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;

  gen_subkey_type = params.subkey_type;
  gen_subkey_length = params.subkey_length;
  gen_subkey_expire = params.subkey_expire;
  gen_sign_flag = params.sign_flag;
  gen_enc_flag = params.enc_flag;
  gen_auth_flag = params.auth_flag;

  err = gpgme_get_key(ctx, params.keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_set_progress_cb (ctx, cb_status, APIObj);

  edit_status = "gpgGenSubKeyWorker(keyid='" + params.keyid +
      "', subkey_type='" + params.subkey_type + "', subkey_length='" +
      params.subkey_length + "', subkey_expire='" + params.subkey_expire +
      "', sign_flag='" + i_to_str(params.sign_flag) + "', enc_flag='" +
      i_to_str(params.enc_flag) + "', auth_flag='" +
      i_to_str(params.auth_flag) + "');\n";
  current_edit = WEBPG_EDIT_ADDSUBKEY;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);

  if (err != GPG_ERR_NO_ERROR) {
    if (gpg_err_code(err) == GPG_ERR_CANCELED)
      g_callback("onkeygencomplete", "failed: cancelled");
    else if (gpg_err_code(err) == GPG_ERR_BAD_PASSPHRASE)
      g_callback("onkeygencomplete", "failed: bad passphrase");

    return get_error_map(__func__, err, __LINE__, __FILE__);
  }

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  // Restore the options to normal
  restoreGPGConfig();

  const char* status = (char *) "complete";
  cb_status(APIObj, status, 33, 33, 33);
  return "done";
}

///////////////////////////////////////////////////////////////////////////////
/// @fn std::string gpgGenKey(const std::string& key_type,
///                           const std::string& key_length,
///                           const std::string& subkey_type,
///                           const std::string& subkey_length,
///                           const std::string& name_real,
///                           const std::string& name_comment,
///                           const std::string& name_email,
///                           const std::string& expire_date,
///                           const std::string& passphrase,
///                           GENKEY_ROGRESS_CB callback)
///
/// @brief  Queues a threaded gpg genkey operation.
///
/// @param  key_type    The key type to genereate.
/// @param  key_length    The size of the key to generate.
/// @param  subkey_type   The subkey type to generate.
/// @param  subkey_length   The size of the subkey to genereate.
/// @param  name_real   The name to assign the UID.
/// @param  name_comment    The comment to assign to the UID.
/// @param  name_email  The email address to assign to the UID.
/// @param  expire_date The expiration date to assign to the generated key.
/// @param  passphrase  The passphrase to assign the to the key.
///////////////////////////////////////////////////////////////////////////////
std::string webpg::gpgGenKey(
    const std::string& key_type,
    const std::string& key_length,
    const std::string& subkey_type,
    const std::string& subkey_length,
    const std::string& name_real,
    const std::string& name_comment,
    const std::string& name_email,
    const std::string& expire_date,
    const std::string& passphrase,
    GENKEY_PROGRESS_CB callback
) {

  genKeyParams params;

  params.key_type = key_type;
  params.key_length = key_length;
  params.subkey_type = subkey_type;
  params.subkey_length = subkey_length;
  params.name_real = name_real;
  params.name_comment = name_comment;
  params.name_email = name_email;
  params.expire_date = expire_date;
  params.passphrase = passphrase;

  if (callback) {
#ifndef H_LIBWEBPG
    g_callback = nativeCallback;
#else
    g_callback = callback;
#endif
    webpg::gpgGenKeyWorker(params, this, &webpg::genkey_progress_cb);
  } else {
#ifndef H_LIBWEBPG
    g_callback = nativeCallback;
    webpg::gpgGenKeyWorker(params, this, &webpg::genkey_progress_cb);
#else
    webpg::gpgGenKeyWorker(params, this, NULL);
#endif
  }

  return "queued";
}

///////////////////////////////////////////////////////////////////////////////
/// @fn std::string gpgGenSubKey(const std::string& keyid,
///                              const std::string& subkey_type,
///                              const std::string& subkey_length,
///                              const std::string& subkey_expire,
///                              bool sign_flag,
///                              bool enc_flag,
///                              bool auth_flag,
///                              GENKEY_PROGRESS_CB callback)
///
/// @brief  Queues a threaded gpg gensubkey operation.
///
/// @param  keyid    The key to generate the subkey on.
/// @param  subkey_type   The subkey type to generate.
/// @param  subkey_length   The size of the subkey to genereate.
/// @param  subkey_expire The expiration date to assign to the generated subkey.
/// @param  sign_flag  Set the sign capabilities flag.
/// @param  enc_flag    Set the encrypt capabilities flag.
/// @param  auth_flag  Set the auth capabilities flag.
///////////////////////////////////////////////////////////////////////////////
std::string webpg::gpgGenSubKey(
    const std::string& keyid,
    const std::string& subkey_type,
    const std::string& subkey_length,
    const std::string& subkey_expire,
    bool sign_flag,
    bool enc_flag,
    bool auth_flag,
    GENKEY_PROGRESS_CB callback
) {

  genSubKeyParams params;

  params.keyid = keyid;
  params.subkey_type = subkey_type;
  params.subkey_length = subkey_length;
  params.subkey_expire = subkey_expire;
  params.sign_flag = sign_flag;
  params.enc_flag = enc_flag;
  params.auth_flag = auth_flag;

  if (callback != NULL) {
#ifndef H_LIBWEBPG
    g_callback = nativeCallback;
#else
    g_callback = callback;
#endif
    webpg::gpgGenSubKeyWorker(params, this, &webpg::genkey_progress_cb);
  } else {
#ifndef H_LIBWEBPG
    g_callback = nativeCallback;
    webpg::gpgGenSubKeyWorker(params, this, &webpg::genkey_progress_cb);
#else
    webpg::gpgGenSubKeyWorker(params, this, NULL);
#endif
  }

  return "queued";
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgImportKey(const std::string& ascii_key)
///
/// @brief  Imports the ASCII encoded key ascii_key
///
/// @param  ascii_key   An armored, ascii encoded PGP Key block.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgImportKey(const std::string& ascii_key)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t key_buf;
  gpgme_import_result_t result;

  err = gpgme_data_new_from_mem (&key_buf,
                                 ascii_key.c_str(),
                                 ascii_key.length(),
                                 1);

  err = gpgme_op_import (ctx, key_buf);

  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  result = gpgme_op_import_result (ctx);
  gpgme_data_release (key_buf);

  Json::Value status;

  status["considered"] = result->considered;
  status["no_user_id"] = result->no_user_id;
  status["imported"] = result->imported;
  status["imported_rsa"] = result->imported_rsa;
  status["new_user_ids"] = result->new_user_ids;
  status["new_sub_keys"] = result->new_sub_keys;
  status["new_signatures"] = result->new_signatures;
  status["new_revocations"] = result->new_revocations;
  status["secret_read"] = result->secret_read;
  status["secret_imported"] = result->secret_imported;
  status["secret_unchanged"] = result->secret_unchanged;
  status["not_imported"] = result->not_imported;

  Json::Value imports_map;
  int nimport = 0;
  gpgme_import_status_t imp;
  for (nimport=0, imp=result->imports; imp; imp = imp->next, nimport++) {
    Json::Value imp_item_map;
    imp_item_map["fingerprint"] = nonnull (imp->fpr);
    imp_item_map["result"] = gpgme_strerror(imp->result);
    imp_item_map["status"] = imp->status;
    imp_item_map["new_key"] = imp->status & GPGME_IMPORT_NEW? true : false;
    imp_item_map["new_uid"] = imp->status & GPGME_IMPORT_UID? true : false;
    imp_item_map["new_sig"] = imp->status & GPGME_IMPORT_SIG? true : false;
    imp_item_map["new_subkey"] =
      imp->status & GPGME_IMPORT_SUBKEY? true : false;
    imp_item_map["new_secret"] =
      imp->status & GPGME_IMPORT_SECRET? true : false;
    imports_map[i_to_str(nimport)] = imp_item_map;
  }
  status["imports"] = imports_map;
  gpgme_release (ctx);

  return status;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgImportExternalKey(const std::string& keyid)
///
/// @brief  Imports a public key from the configured keyserver
///
/// @param  keyid   The KeyID of the Public Key to import
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgImportExternalKey(const std::string& keyid)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_import_result_t result;
  gpgme_key_t extern_key,
              key_array[2];

  err = gpgme_set_keylist_mode(ctx, GPGME_KEYLIST_MODE_EXTERN);

  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_get_key(ctx, (char *) keyid.c_str(), &extern_key, 0);

  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  key_array[0] = extern_key;
  key_array[1] = NULL;

  std::cerr << extern_key->subkeys->keyid << std::endl;

  err = gpgme_op_import_keys (ctx, key_array);

  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  result = gpgme_op_import_result (ctx);

  Json::Value status;

  status["considered"] = result->considered;
  status["no_user_id"] = result->no_user_id;
  status["imported"] = result->imported;
  status["imported_rsa"] = result->imported_rsa;
  status["new_user_ids"] = result->new_user_ids;
  status["new_sub_keys"] = result->new_sub_keys;
  status["new_signatures"] = result->new_signatures;
  status["new_revocations"] = result->new_revocations;
  status["secret_read"] = result->secret_read;
  status["secret_imported"] = result->secret_imported;
  status["secret_unchanged"] = result->secret_unchanged;
  status["not_imported"] = result->not_imported;

  Json::Value imports_map;
  int nimport = 0;
  gpgme_import_status_t import;
  for (nimport=0, import=result->imports; import; import = import->next,
       nimport++) {
    Json::Value import_item_map;
    std::cerr <<  gpgme_strerror(import->result) << std::endl;
    import_item_map["fingerprint"] = nonnull (import->fpr);
    import_item_map["result"] = gpgme_strerror(import->result);
    import_item_map["status"] = import->status;
    import_item_map["new_key"] =
      import->status & GPGME_IMPORT_NEW? true : false;
    import_item_map["new_uid"] =
      import->status & GPGME_IMPORT_UID? true : false;
    import_item_map["new_sig"] =
      import->status & GPGME_IMPORT_SIG? true : false;
    import_item_map["new_subkey"] =
      import->status & GPGME_IMPORT_SUBKEY? true : false;
    import_item_map["new_secret"] =
      import->status & GPGME_IMPORT_SECRET? true : false;
    imports_map[i_to_str(nimport)] = import_item_map;
  }
  status["imports"] = imports_map;
  gpgme_key_unref (extern_key);
  gpgme_release (ctx);

  return status;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgDeleteKey(const std::string& keyid, int allow_secret)
///
/// @brief  Deletes the key specified in keyid from the keyring.
///
/// @param  allow_secret   Enables deleting the key from the private keyring.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgDeleteKey(const std::string& keyid, int allow_secret)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_key_t key = NULL;
  Json::Value response;

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_op_delete(ctx, key, allow_secret);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["result"] = "Key deleted";

  return response;
}

/*
    This method executes webpg.gpgDeleteKey with the allow_secret=0,
        which allows it to only delete public Public Keys from the keyring.
*/
///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgDeletePublicKey(const std::string& keyid)
///
/// @brief  Deletes key specified in keyid from the Public keyring.
///
/// @param  keyid   The ID of the key to delete from the Public keyring.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgDeletePublicKey(const std::string& keyid)
{
  return webpg::gpgDeleteKey(keyid, 0);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgDeletePrivateKey(const std::string& keyid)
///
/// @brief  Deletes key specified in keyid from the Private keyring.
///
/// @param  keyid   The ID of the key to delete from the Private keyring.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgDeletePrivateKey(const std::string& keyid)
{
  return webpg::gpgDeleteKey(keyid, 1);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgDeletePrivateSubKey(const std::string& keyid,
///                                        int key_idx)
///
/// @brief  Deletes subkey located at index of the key specified in <keyid>.
///
/// @param  keyid   The ID of the key to delete the subkey from.
/// @param  key_idx The index of the subkey to delete.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgDeletePrivateSubKey(
    const std::string& keyid,
    int key_idx
) {
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;

  akey_index = i_to_str(key_idx);

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgDeletePrivateSubkey(keyid='" + keyid + "', key_idx='" +
                  i_to_str(key_idx) + "');\n";
  current_edit = WEBPG_EDIT_DELSUBKEY;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  akey_index = "";

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["edit_status"] = edit_status;
  response["result"] = "Subkey Delete";

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSetKeyTrust(const std::string& keyid, long trust_level)
///
/// @brief  Sets the gnupg trust level assignment for the given keyid.
///
/// @param  keyid   The ID of the key to assign the trust level on.
/// @param  trust_level The level of trust to assign.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSetKeyTrust(const std::string& keyid, long trust_level)
{
    gpgme_ctx_t ctx = get_gpgme_ctx();
    gpgme_error_t err;
    gpgme_data_t out = NULL;
    gpgme_key_t key = NULL;
    Json::Value response;
    trust_assignment = i_to_str(trust_level);

  if (trust_level < 1) {
    response["error"] = true;
    response["result"] = "Valid trust assignment values are 1 through 5";
    return response;
  }

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgSetKeyTrust(keyid='" + keyid + "', trust_level='" +
      i_to_str(trust_level) + "');\n";
  current_edit = WEBPG_EDIT_ASSIGN_TRUST;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  trust_assignment = "0";

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["result"] = "trust value assigned";

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgAddUID(const std::string& keyid,
///                           const std::string& name,
///                           const std::string& email,
///                           const std::string& comment)
///
/// @brief  Adds a new UID to the key specified by keyid.
///
/// @param  keyid   The ID of the key to add the UID to.
/// @param  name    The name to assign to the new UID.
/// @param  email   The email address to assign to the new UID.
/// @param  comment The comment to assign to the new UID.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgAddUID(
    const std::string& keyid,
    const std::string& name,
    const std::string& email,
    const std::string& comment
) {
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;
  genuid_name = name;
  genuid_email = email;
  genuid_comment = comment;

  if (isdigit(name.c_str()[0]))
    return get_error_map(__func__, GPG_ERR_INV_NAME, __LINE__, __FILE__);

  if (strlen (name.c_str()) < 5)
    return get_error_map(__func__, GPG_ERR_TOO_SHORT, __LINE__, __FILE__);

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgAddUID(keyid='" + keyid + "', name='" + name +
                  "', email='" + email + "', comment='" + comment + "');\n";

  current_edit = WEBPG_EDIT_ADD_UID;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  response["name"] = genuid_name;
  response["email"] = genuid_email;
  response["comment"] = genuid_comment;

  genuid_name = "";
  genuid_email = "";
  genuid_comment = "";

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["edit_status"] = edit_status;
  response["result"] = "UID added";

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgDeleteUID(const std::string& keyid, long uid_idx)
///
/// @brief  Deletes the UID specified by uid_idx from the specified key.
///
/// @param  keyid   The ID of the key to delete to the specified UID from.
/// @param  uid_idx The index of the UID to delete from the key.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgDeleteUID(const std::string& keyid, long uid_idx)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;

  if (uid_idx < 1)
    return get_error_map(__func__, GPG_ERR_INV_INDEX, __LINE__, __FILE__);

  current_uid = i_to_str(uid_idx);

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgDeleteUID(keyid='" + keyid + "', uid_idx='" +
                  i_to_str(uid_idx) + "');\n";
  current_edit = WEBPG_EDIT_DEL_UID;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);


  current_uid = "0";

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["edit_status"] = edit_status;
  response["result"] = "UID deleted";

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSetPrimaryUID(const std::string& keyid, long uid_idx)
///
/// @brief  Sets a given UID as the primary for the key specified with keyid.
///
/// @param  keyid   The ID of the key with the UID to make primary.
/// @param  uid_idx The index of the UID to make primary on the key.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSetPrimaryUID(const std::string& keyid, long uid_idx)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;

  if (uid_idx < 1)
    return get_error_map(__func__, GPG_ERR_INV_INDEX, __LINE__, __FILE__);

  current_uid = i_to_str(uid_idx);

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgSetPrimaryUID(keyid='" + keyid + "', uid_idx='" +
                  i_to_str(uid_idx) + "');\n";
  current_edit = WEBPG_EDIT_SET_PRIMARY_UID;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);


  current_uid = "0";

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["edit_status"] = edit_status;
  response["result"] = "Primary UID changed";

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSetKeyExpire(const std::string& keyid,
///                                 long key_idx,
///                                 long expire)
///
/// @brief  Sets the expiration of the given key_idx on the key keyid with the
///         expiration of expire.
///
/// @param  keyid   The ID of the key to set the expiration on.
/// @param  key_idx The index of the subkey to set the expiration on.
/// @param  expire  The expiration to assign.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSetKeyExpire(
    const std::string& keyid,
    long key_idx,
    long expire
) {
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;

  akey_index = i_to_str(key_idx);
  expiration = i_to_str(expire);

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgSetKeyExpire(keyid='" + keyid + "', key_idx='" +
                  i_to_str(key_idx) + "', expire='" +
                  i_to_str(expire) + "');\n";
  current_edit = WEBPG_EDIT_SET_KEY_EXPIRE;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);


  akey_index = "";
  expiration = "";

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["edit_status"] = edit_status;
  response["result"] = "Expiration changed";

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSetPubkeyExpire(const std::string& keyid, long expire)
///
/// @brief  Sets the expiration of the public key of the given keyid.
///
/// @param  keyid   The ID of the key to set the expiration on.
/// @param  expire  The expiration to assign to the key.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSetPubkeyExpire(const std::string& keyid, long expire)
{
  return webpg::gpgSetKeyExpire(keyid, 0, expire);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgSetSubkeyExpire(const std::string& keyid,
///                                    long key_idx,
///                                    long expire)
///
/// @brief  Sets the expiration of the subkey specified with key_idx on the key
///         specified with keyid.
///
/// @param  keyid   The ID of the key to set the expiration on.
/// @param  key_idx The index of the subkey to set the expiration on.
/// @param  expire  The expiration to assign to the key.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgSetSubkeyExpire(
    const std::string& keyid,
    long key_idx,
    long expire
) {
  return webpg::gpgSetKeyExpire(keyid, key_idx, expire);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgExportPublicKey(const std::string& keyid)
///
/// @brief  Exports the public key specified with <keyid> as an ASCII armored
///         PGP Block.
///
/// @param  keyid   The ID of the Public key to export.
///
/// @returns Json::Value response
/*! @verbatim
response {
  "error":false,
  "result":"—————BEGIN PGP PUBLIC KEY BLOCK—————
          Version: GnuPG v1.4.11 (GNU/Linux)

          mQENBE4u4h8BCADCtBh7btjjKMGVsbjTUKSl69M3bbeBgjR/jMBtYFEJmC0ZnPE9
          ... truncated ...
          uOIPbsuvGT06lotLoalLgA==
          =bq+M
          —————END PGP PUBLIC KEY BLOCK—————"
}
@endverbatim
*/
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgExportPublicKey(const std::string& keyid)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  Json::Value response;

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_op_export (ctx, keyid.c_str(), 0, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_data_seek(out, 0, SEEK_SET);

  size_t out_size = 0;
  std::string out_buf;
  out_buf = gpgme_data_release_and_get_mem (out, &out_size);
  /* strip the size_t data out of the output buffer */
  out_buf = out_buf.substr(0, out_size);
  /* set the output object to NULL since it has
      already been released */
  out = NULL;

  gpgme_release (ctx);

#ifndef H_LIBWEBPG
  int c = 1;
  unsigned int buf_len = out_buf.length();
  float max_len = 500000.0;
  int chunks = ceil(buf_len/max_len);
  chunks = chunks == 0 ? 1 : chunks;
  Json::FastWriter writer;
  std::string ret;
  Json::Value chunklist(Json::arrayValue);
  chunklist[1] = chunks;
  std::cerr << chunks << std::endl;
  if (chunks > 1) {
    Json::Value chunked_response;
    chunked_response["error"] = false;
    unsigned int start, end;
    while (c < chunks + 1) {
      chunklist[0] = c;
      start = max_len * (c-1);
      end = max_len * c;
      if (end > buf_len)
        end = buf_len;
      chunked_response["chunk"] = chunklist;
      chunked_response["result"] = out_buf.substr(start, end);
      c++;
      ret = writer.write(chunked_response);
      chunked_response.clear();
      nativeCallback("export-progress", ret.c_str());
    }
  } else {
    chunklist[0] = 1;
    response["chunk"] = chunklist;
    response["result"] = out_buf;
    ret = writer.write(response);
    nativeCallback("export-progress", ret.c_str());
  }
  return "complete";
#else
  response["error"] = false;
  response["result"] = out_buf;
  return response;
#endif
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgPublishPublicKey(const std::string& keyid)
///
/// @brief  Exports the ASCII armored key specified by <keyid> to the
///         configured keyserver
///
/// @param  keyid   The ID of the Public key to export.
///
/// @returns Json::Value response
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgPublishPublicKey(const std::string& keyid)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_key_t key;
  gpgme_key_t key_array[2];
  gpgme_export_mode_t mode = 0;
  Json::Value response;

  Json::Value keyserver_option = webpg::gpgGetPreference("keyserver");
  if (keyserver_option["value"] == "") {
    response["error"] = true;
    response["result"] = "No keyserver defined";
    return response;
  }

  err = gpgme_get_key(ctx, (char *) keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  key_array[0] = key;
  key_array[1] = NULL;

  mode |= GPGME_KEYLIST_MODE_EXTERN;

  err = gpgme_op_export_keys (ctx, key_array, mode, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["result"] = "Exported";

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgRevokeItem(const std::string& keyid,
///                               const std::string& item,
///                               int key_idx,
///                               int uid_idx,
///                               int sig_idx,
///                               int reason,
///                               const std::string& desc)
///
/// @brief  Revokes a give key, trust item, subkey, uid or signature with the
///         specified reason and description.
///
/// @param  keyid   The ID of the key with the item to revoke.
/// @param  item    The item to revoke.
/// @param  key_idx The index of the subkey to revoke.
/// @param  uid_idx The index of the UID to revoke.
/// @param  sig_idx The index of the signature to revoke.
/// @param  reason  The gnupg reason for the revocation.
/// @param  desc    The text description for the revocation.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgRevokeItem(
    const std::string& keyid,
    const std::string& item,
    int key_idx,
    int uid_idx,
    int sig_idx,
    int reason,
    const std::string& desc
) {

  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;

  akey_index = i_to_str(key_idx);
  current_uid = i_to_str(uid_idx);
  current_sig = i_to_str(sig_idx);
  revitem = item.c_str();
  reason_index = i_to_str(reason);
  description = desc.c_str();

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgRevokeItem(keyid='" + keyid + "', item='" + item +
      "', key_idx='" + i_to_str(key_idx) + "', uid_idx='" + i_to_str(uid_idx) +
      "', sig_idx='" + i_to_str(sig_idx) + "', reason='" + i_to_str(reason) +
      "', desc='" + desc + "');\n";

  current_edit = WEBPG_EDIT_REVOKE_ITEM;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);


  akey_index = "";
  reason_index = "";
  current_uid = "";

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["edit_status"] = edit_status;
  response["result"] = "Item Revoked";

  return response;
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgRevokeKey(const std::string& keyid,
///                              int key_idx,
///                              int reason,
///                              const std::string &desc)
///
/// @brief  Revokes the given key/subkey with the reason and description given.
///
/// @param  keyid   The ID of the key to revoke.
/// @param  key_idx The index of the subkey to revoke.
/// @param  reason  The gnupg reason for the revocation.
/// @param  desc    The text description for the revocation.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgRevokeKey(
    const std::string& keyid,
    int key_idx,
    int reason,
    const std::string &desc
) {
  return webpg::gpgRevokeItem(keyid, "revkey", key_idx, 0, 0, reason, desc);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgRevokeUID(const std::string& keyid,
///                              int uid_idx,
///                              int reason,
///                              const std::string &desc)
///
/// @brief  Revokes the given UID with the reason and description given.
///
/// @param  keyid   The ID of the key with the UID to revoke.
/// @param  uid_idx The index of the UID to revoke.
/// @param  reason  The gnupg reason for the revocation.
/// @param  desc    The text description for the revocation.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgRevokeUID(
    const std::string& keyid,
    int uid_idx,
    int reason,
    const std::string &desc
) {
  if (reason != 0 && reason != 4) {
    Json::Value response;
    response["error"] = true;
    response["result"] = "Valid reason assignment values are 0 or 4";
    return response;
  }
  return webpg::gpgRevokeItem(keyid, "revuid", 0, uid_idx, 0, reason, desc);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgRevokeSignature(const std::string& keyid,
///                                    int uid_idx,
///                                    int sig_idx,
///                                    int reason,
///                                    const std::string &desc)
///
/// @brief  Revokes the given signature on the specified UID of key <keyid>
//          with the reason and description specified.
///
/// @param  keyid   The ID of the key with the signature to revoke.
/// @param  uid_idx The index of the UID with the signature to revoke.
/// @param  sig_idx The index of the signature to revoke.
/// @param  reason  The gnupg reason for the revocation.
/// @param  desc    The text description for the revocation.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgRevokeSignature(
    const std::string& keyid,
    int uid_idx,
    int sig_idx,
    int reason,
    const std::string &desc
) {
  return webpg::gpgRevokeItem(keyid, "revsig", 0, uid_idx, sig_idx, reason,
                              desc);
}

///////////////////////////////////////////////////////////////////////////////
/// @fn Json::Value gpgChangePassphrase(const std::string& keyid)
///
/// @brief  Invokes the gpg-agent to change the passphrase for the given key.
///
/// @param  keyid   The ID of the key to change the passphrase.
///////////////////////////////////////////////////////////////////////////////
Json::Value webpg::gpgChangePassphrase(const std::string& keyid)
{
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value result;

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 1);

  if (err != GPG_ERR_NO_ERROR)
    result = get_error_map(__func__, err, __LINE__, __FILE__);

  if (!key)
    result = get_error_map(__func__, GPG_ERR_NOT_FOUND, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    result = get_error_map(__func__, err, __LINE__, __FILE__);

  if (key) {
    edit_status = "gpgChangePassphrase(keyid='" + keyid + "');\n";
    current_edit = WEBPG_EDIT_PASSPHRASE;
    err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  }

  if (err != GPG_ERR_NO_ERROR)
    result = get_error_map(__func__, err, __LINE__, __FILE__);

  Json::Value response;
  if (!key || !key->secret) {
    response["error"] = true;
    response["result"] = "no secret";
  } else {
    response["error"] = false;
    response["result"] = "success";
  }

  if (out)
    gpgme_data_release (out);
  if (key)
    gpgme_key_unref (key);
  gpgme_release (ctx);

  if (result.size())
    return result;

  return response;
}

/*
    This method ensures a given UID <domain> with matching keyid
        <domain_key_fpr> has been signed by a required key
        <required_sig_keyid> and returns a GAU_trust value as the result.
        This method is intended to be called during an iteration of
        trusted key ids.
*/
    //TODO: Make these values constants and replace the usages below
    //  to use the constants
    //TODO: Add this list of constants to the documentation
    /* verifyDomainKey returns a numeric trust value -
        -7: the domain UID and/or domain key was signed by an expired key
        -6: the domain UID and/or domain key was signed by a key that
            has been revoked
        -5: the domain uid was signed by a disabled key
        -4: the  sinature has been revoked, disabled or is invalid
        -3: the uid has been revoked or is disabled or invalid.
        -2: the key belonging to the domain has been revoked or disabled, or
             is invalid.
        -1: the domain uid was not signed by any enabled private key and fails
             web-of-trust
        0: UID of domain_keyid was signed by an ultimately trusted private key
        1: UID of domain_keyid was signed by an expired private key that is
            ultimately trusted
        2: UID of domain_keyid was signed by a private key that is other than
            ultimately trusted
        3: UID of domain_keyid was signed by an expired private key that is
            other than ultimately trusted
        4: domain_keyid was signed (not the UID) by an ultimately trusted
            private key
        5: domain_key was signed (not the UID) by an expired ultimately trusted
            key
        6: domain_keyid was signed (not the UID) by an other than ultimately
            trusted private key
        7: domain_key was signed (not the UID) by an expired other than
            ultimately trusted key
        8: domain_keyid was not signed, but meets web of trust
            requirements (i.e.: signed by a key that the user
            trusts and has signed, as defined by the user
            preference of "advnaced.trust_model")
    */
int webpg::verifyDomainKey(
    const std::string& domain,
    const std::string& domain_key_fpr,
    long uid_idx,
    const std::string& required_sig_keyid
) {
  int nuids;
  int nsig;
  int domain_key_valid = -1;
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_key_t domain_key = NULL, user_key, secret_key, key;
  gpgme_user_id_t uid;
  gpgme_key_sig_t sig;
  gpgme_error_t err;

  gpgme_set_keylist_mode (ctx, (gpgme_get_keylist_mode (ctx)
                                | GPGME_KEYLIST_MODE_LOCAL
                                | GPGME_KEYLIST_MODE_SIGS));

  err = gpgme_op_keylist_start (ctx, (char *) domain_key_fpr.c_str(), 0);
  if (err != GPG_ERR_NO_ERROR) return -1;

  err = gpgme_get_key(ctx, (char *) required_sig_keyid.c_str(), &user_key, 0);
  if(err != GPG_ERR_NO_ERROR) return -1;

  if (user_key) {
    while (!(err = gpgme_op_keylist_next (ctx, &domain_key))) {
      for (nuids=0, uid=domain_key->uids; uid; uid = uid->next, nuids++) {
        for (nsig=0, sig=uid->signatures; sig; sig = sig->next, nsig++) {
          if (domain_key->disabled) {
            domain_key_valid = -2;
            break;
          }
          if (!strcmp(uid->name, (char *) domain.c_str())
              && (uid_idx == nuids || uid_idx == -1)) {
            if (uid->revoked)
              domain_key_valid = -3;
            if (!strcmp(sig->keyid, (char *) required_sig_keyid.c_str())) {
              if (user_key->owner_trust == GPGME_VALIDITY_ULTIMATE)
                domain_key_valid = 0;
              if (user_key->owner_trust == GPGME_VALIDITY_FULL)
                domain_key_valid = 2;
              if (user_key->expired)
                domain_key_valid++;
              if (sig->invalid)
                domain_key_valid = -4;
              if (sig->revoked)
                domain_key_valid = -4;
              if (sig->expired)
                domain_key_valid = -4;
              if (user_key->disabled)
                domain_key_valid = -5;
              if (sig->status == GPG_ERR_NO_PUBKEY)
                domain_key_valid = -1;
              if (sig->status == GPG_ERR_GENERAL)
                domain_key_valid = -1;
              // the key trust is 0 (best), stop searching
              if (domain_key_valid == 0)
                break;
            }
          }
        }
      }
    }

    if (gpg_err_code (err) != GPG_ERR_EOF) return -1;
    gpgme_get_key(ctx, (char *) domain_key_fpr.c_str(), &domain_key, 0);
    err = gpgme_op_keylist_end (ctx);
    if(err != GPG_ERR_NO_ERROR) return -1;

    gpgme_keylist_result_t result = gpgme_op_keylist_result (ctx);

    if (!result && result->truncated == 1)
      return -1;

    // the UID failed the signature test, check to see if the primary UID was
    // signed by one permissible key, or a trusted key.
    if (domain_key_valid == -1) {
      for (nuids=0, uid=domain_key->uids; uid; uid = uid->next, nuids++) {
        for (nsig=0, sig=uid->signatures; sig; sig=sig->next, nsig++) {
          if (sig->status != GPG_ERR_NO_ERROR)
            continue;
          // the signature keyid matches the required_sig_keyid
          if (nuids == uid_idx && domain_key_valid == -1) {
            err = gpgme_get_key(ctx, (char *) sig->keyid, &key, 0);
            if(err != GPG_ERR_NO_ERROR) return -1;
            err = gpgme_get_key(ctx, (char *) sig->keyid, &secret_key, 1);
            if(err != GPG_ERR_NO_ERROR) return -1;
            if (key && key->owner_trust == GPGME_VALIDITY_ULTIMATE) {
              if (!secret_key) {
                domain_key_valid = 8;
              } else {
                domain_key_valid = 4;
              }
            }
            if (key && key->owner_trust == GPGME_VALIDITY_FULL) {
              if (!secret_key) {
                domain_key_valid = 8;
              } else {
                domain_key_valid = 6;
              }
            }
            if (key && key->expired && domain_key_valid < -1)
              domain_key_valid += -1;
            if (key && key->expired && domain_key_valid >= 0) {
              domain_key_valid++;
            }
            if (sig->expired)
              domain_key_valid = -6;
            if (sig->invalid)
              domain_key_valid = -2;
            if (uid->revoked || sig->revoked)
              domain_key_valid = -6;
            if (sig->status == GPG_ERR_NO_PUBKEY)
              domain_key_valid = -1;
            if (sig->status == GPG_ERR_GENERAL)
              domain_key_valid = -1;
            if (key)
              gpgme_key_unref (key);
            if (secret_key)
              gpgme_key_unref (secret_key);
          }
          if (!strcmp(sig->keyid, (char *) required_sig_keyid.c_str())) {
            if (nuids == 0) {
              if (user_key && user_key->owner_trust == GPGME_VALIDITY_ULTIMATE)
                domain_key_valid = 4;
              if (user_key && user_key->owner_trust == GPGME_VALIDITY_FULL)
                domain_key_valid = 6;
              if (user_key && user_key->expired)
                domain_key_valid++;
              if (sig->expired)
                domain_key_valid = -6;
              if (sig->invalid)
                domain_key_valid = -2;
              if (uid->revoked || sig->revoked)
                domain_key_valid = -6;
              if (sig->status == GPG_ERR_NO_PUBKEY)
                domain_key_valid = -1;
              if (sig->status == GPG_ERR_GENERAL)
                domain_key_valid = -1;
            }
          }
        }
      }
    }
  }

  if (domain_key)
    gpgme_key_unref (domain_key);
  if (user_key)
    gpgme_key_unref (user_key);

  if (ctx)
    gpgme_release (ctx);

  return domain_key_valid;
}

void webpg::gpgShowPhoto(const std::string& keyid) {
  gpgme_error_t err;
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_ctx_t edit_ctx = get_gpgme_ctx();
  gpgme_key_t key;
  gpgme_set_keylist_mode (ctx,
    (gpgme_get_keylist_mode (ctx) |
    (GPGME_KEYLIST_MODE_LOCAL &
    ~GPGME_KEYLIST_MODE_SIGS &
    ~GPGME_KEYLIST_MODE_SIG_NOTATIONS))
  );
  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err ==  GPG_ERR_NO_ERROR) {
    gpgme_data_t out;
    gpgme_data_new (&out);
    current_edit = WEBPG_EDIT_SHOW_PHOTO;
    gpgme_op_edit (edit_ctx, key, edit_fnc, out, out);
    gpgme_data_release (out);
  }
  if (key)
    gpgme_key_unref (key);
  gpgme_release (ctx);
};

Json::Value webpg::gpgAddPhoto(
    const std::string& keyid,
    const std::string& photo_name,
    const std::string& photo_data
) {
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  Json::Value response;
  std::string temp_path;

  char *temp_envvar = getenv("TEMP");
  if (temp_envvar != NULL) {
    temp_path = temp_envvar;
    temp_path += "/";
  } else
    temp_path = "/tmp/";

  temp_path = temp_path +  photo_name;

  std::ofstream tmp_photo(temp_path.c_str(),
    std::ios::out | std::ios::trunc | std::ios::binary);

  if (!tmp_photo) {
    response["error"] = true;
    response["error_string"] = "Unable to create temporary file";
    return response;
  }

  typedef transform_width<binary_from_base64<remove_whitespace
    <std::string::const_iterator> >, 8, 6 > it_binary_t;

  unsigned int paddChars = std::count(photo_data.begin(),
                                      photo_data.end(), '=');
  std::string data(strdup(photo_data.c_str()));
  std::replace(data.begin(), data.end(), '=', 'A');
  std::string result(it_binary_t(data.begin()), it_binary_t(data.end()));
  result.erase(result.end()-paddChars,result.end());
  tmp_photo << result;
  tmp_photo.close();

  photo_path = temp_path;

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  err = gpgme_data_new (&out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  edit_status = "gpgAddPhoto(keyid='" + keyid + "', path='" + photo_path + "');\n";

  current_edit = WEBPG_EDIT_ADD_PHOTO;
  err = gpgme_op_edit (ctx, key, edit_fnc, out, out);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  response["keyid"] = keyid;
  response["photo_path"] = photo_path;
  remove(temp_path.c_str());

  photo_path = "";

  gpgme_data_release (out);
  gpgme_key_unref (key);
  gpgme_release (ctx);

  response["error"] = false;
  response["edit_status"] = edit_status;
  response["result"] = "Photo added";

  return response;
}

Json::Value webpg::gpgGetPhotoInfo(const std::string& keyid) {
  gpgme_ctx_t ctx = get_gpgme_ctx();
  gpgme_error_t err;
  gpgme_data_t out = NULL;
  gpgme_key_t key = NULL;
  gpgme_user_id_t uid;
  Json::Value response;
  size_t out_size = 0;
  int nuids = 0;

  err = gpgme_get_key(ctx, keyid.c_str(), &key, 0);
  if (err != GPG_ERR_NO_ERROR)
    return get_error_map(__func__, err, __LINE__, __FILE__);

  /* check for a photo */
  gpgme_data_new (&out);
  current_edit = WEBPG_EDIT_CHECK_PHOTO;
  gpgme_op_edit (ctx, key, edit_fnc, NULL, out);
  std::string out_buf = gpgme_data_release_and_get_mem (out, &out_size);

  response["photos_provided"] = 0;

  std::string s = "uat:";

  if (out_buf.find(s) == std::string::npos) {
    Json::Value photo_map;
    response["photos"] = photo_map;
    return response;
  }

  for (nuids=0, uid=key->uids; uid; uid = uid->next)
    nuids++;

  int photo_count = 0;
  Json::Value photos_map;

  for (size_t offset = out_buf.find(s); offset != std::string::npos;
    offset = out_buf.find(s, offset + s.length())) {
    photo_count++;
    Json::Value photo_map;
    photo_map["relative_index"] = photo_count - 1;
    photo_map["absolute_index"] = nuids + photo_count;
    photos_map[i_to_str(photo_count - 1)] = photo_map;
  }

  response["photos"] = photos_map;
  response["photos_provided"] = photo_count;
  response["photos_path"] = webpg::getTemporaryPath();

  gpgme_key_unref (key);
  gpgme_release (ctx);

  return response;
}

Json::Value webpg::showPhotoCallback(
    const std::string& keyid,
    const std::string& path,
    const std::string& extension,
    int index,
    int count
) {
  Json::Value response;
  struct stat info;
  int i = 0, p_index;
  std::string image;
  std::ofstream photo;

  if (stat(path.c_str(), &info) != 0) {
    std::string cmd = "mkdir " + path;
    system(cmd.c_str());
  }

  while (i < count) {
    p_index = i + index + 1;
    image = path + keyid + '-' + i_to_str(i) + '-' + i_to_str(p_index) + ".j";
    if (stat(image.c_str(), &info) != 0) {
      photo.open(image.c_str(), std::ios::binary);
      while (!std::cin.eof() && !std::cin.bad() && !std::cin.fail()) {
        photo.put(std::cin.get());
      }
      photo.close();

      std::cerr << p_index << std::endl;
      std::cerr << count << std::endl;
      std::cerr << index << std::endl;

      if (p_index == count + index) {
        std::string command = "cp " + image + " " + path + keyid + "-latest." + extension;
        system(command.c_str());
#ifdef HAVE_W32_SYSTEM
        command = "rename " + path + "\\" + keyid + "-*.j\" \"*.jpg\"";
#else
        command = "for file in " + path + "/" + keyid + "*.j; do mv $file ${file}pg; done";
#endif
        system(command.c_str());
      }

      break;
    }
    i++;
  }

  std::string full_path = path + keyid + "-latest." + extension;
  response["photo"] = full_path;
  std::cerr << response << std::endl;
  return response;
}

MultipartMixed* webpg::createMessage(
    const Json::Value& recipients_m,
    const Json::Value& signers,
    int messageType, // Signed, Encrypted
    const std::string& subject,
    const std::string& msgBody,
    const Json::Value& attachments,
    const boost::optional<std::string>& mimeType
) {
  // define the MultipartMixed message envelope
  MultipartMixed* message = new MultipartMixed;
  Json::Value crypto_result;
  std::string mimeTypeValue;
  // Check if mimeType was provided
  if (mimeType)
    mimeTypeValue = *mimeType;
  else
    mimeTypeValue = "text/plain";

  mimeTypeValue += "; charset=ISO-8859-1";

  std::string boundary = "webpg-";
  bool sign = false;

  // Parse the supplied recipient list
  std::string recip_from = recipients_m["from"].asCString();
  Json::Value to_list = recipients_m["to"];
  Json::Value cc_list = recipients_m["cc"];
  Json::Value bcc_list = recipients_m["bcc"];
  Json::Value recip_keys = recipients_m["keys"];

  // Add the timestamp to the envelope
  time_t timestamp = time(NULL);
  char timestamptext[32];
  if (strftime(
      timestamptext,
      sizeof(timestamptext),
      "%a, %d %b %Y %H:%M:%S +0000",
      gmtime(&timestamp)
     )) {
    Field dateField;
    dateField.name("Date");
    dateField.value(timestamptext);
    message->header().push_back(dateField);
  }

  Field mimeVersion_h;
  mimeVersion_h.name("MIME-Version");
  mimeVersion_h.value(WEBPG_MIME_VERSION_STRING);
  message->header().push_back(mimeVersion_h);

  Field webpgVersion_h;
  webpgVersion_h.name("X-WebPG-Version");
  webpgVersion_h.value(WEBPG_VERSION_STRING);
  message->header().push_back(webpgVersion_h);

  // Add the FROM, TO, CC and BCC fields to the envelope
  message->header().from(recip_from.c_str());
  Json::Value lrecip;
  unsigned int nrecip;
  for (nrecip = 0; nrecip < to_list.size(); nrecip++) {
    lrecip = to_list[nrecip];
    message->header().to().push_back((char *) lrecip.asCString());
  }
  for (nrecip = 0; nrecip < cc_list.size(); nrecip++) {
    lrecip = cc_list[nrecip];
    message->header().cc().push_back((char *) lrecip.asCString());
  }
  message->header().subject(subject.c_str());

  Attachment* att;

  if (messageType == WEBPG_PGPMIME_SIGNED) {
    // Create the pgp-signature ContentType and protocol
    message->header().contentType("multipart/signed");
    message->header().contentType().param("micalg", "pgp-sha1");
    message->header().contentType().param("protocol",
      "application/pgp-signature");

    message->body()
      .preamble("This is an OpenPGP/MIME signed message (RFC 4880 and 3156)");

    // create the plain object.
    MimeEntity* plain;
    plain = new MimeEntity();

    // Create the relevent headers for the plain MimeEntity
    plain->header().contentType().set(mimeTypeValue.c_str());
    plain->header().contentTransferEncoding("quoted-printable");

    std::stringstream msgBodyWH;

    plain->body().assign(msgBody.c_str());
    plain->body().push_back(NEWLINE);
    plain->body().push_back(NEWLINE);
    QP::Encoder qp;
    plain->body().code(qp);

    if (attachments.size() > 0) {
      MaxLineLen mll(72);
      MimeEntity* multipart_mixed = new MultipartMixed;
      multipart_mixed->header().contentTransferEncoding("quoted-printable");
      multipart_mixed->body()
        .preamble("This is a multi-part message in MIME format.");
      multipart_mixed->body().parts().push_back(plain);
      for (unsigned int nattach = 0; nattach < attachments.size(); nattach++) {
        att = new Attachment(attachments[nattach]["filename"].asString(),
          ContentType(
              attachments[nattach]["type"].asString(),
              attachments[nattach]["subtype"].asString()
          )
        );
        att->header().contentTransferEncoding("base64");
        att->body().assign(attachments[nattach]["data"].asString());
        att->body().code(mll);
        multipart_mixed->body().parts().push_back(att);
      }
      message->body().parts().push_back(multipart_mixed);
      msgBodyWH << *multipart_mixed;
    } else {
      // Push the plain MimeEntity into the MimeMultipart message
      message->body().parts().push_back(plain);
      msgBodyWH << *plain;
    }

    crypto_result = webpg::gpgSignText(msgBodyWH.str(),
                                       signers,
                                       1);

    if (crypto_result["error"] == true) {
        // If there was an error, change the TO address so we can detect the
        //  error when returning the message.
        message->header().to("webpg-mime-runtime-error@webpg.org");
        // Set the message subject to the error string.
        message->header().subject(crypto_result["error_string"].asCString());
    }

    att = new Attachment("signature.asc",
      ContentType("application","pgp-signature")
    );
    att->header().contentDescription("OpenPGP digital signature");
    att->header().contentTransferEncoding("7bit");
    att->header().contentDisposition("inline; filename=\"signature.asc\"");
    att->body().assign(crypto_result["data"].asString());

  } else {

    if (signers.size() > 0)
        sign = true;

    crypto_result = gpgEncrypt(msgBody,
                               recip_keys,
                               sign,
                               signers);

    if (crypto_result["error"] == true) {
        // If there was an error, change the TO address so we can detect the
        //  error when returning the message.
        message->header().to("webpg-mime-runtime-error@webpg.org");
        // Set the message subject to the error string.
        message->header().subject(crypto_result["error_string"].asCString());
    }

    // Assign the pgp-encrypted ContentType and protocol
    message->header().contentType("multipart/encrypted");
    message
      ->header()
        .contentType()
          .param("protocol", "application/pgp-encrytped");

    // Set the body preamble
    message
      ->body()
        .preamble("This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)");

    // Add the PGP Mime Version information
    MimeEntity* pgpMimeVersion = new MimeEntity();

    // Create the relevent headers for the PGP Mime Version MimeEntity
    pgpMimeVersion->header()
                    .contentType()
                    .set("application/pgp-encrypted");
    pgpMimeVersion->header()
                    .contentDescription("PGP/MIME version identification");
    pgpMimeVersion->header()
                    .contentDisposition("inline; filename=\"version.asc\"");
    pgpMimeVersion->body().assign("Version: 1");
    pgpMimeVersion->body().push_back(NEWLINE);

    message->body().parts().push_back(pgpMimeVersion);

    att = new Attachment("encrypted.asc",
      ContentType("application","octet-stream")
    );
    att->header().contentDescription("OpenPGP encrypted message");
    att->header().contentTransferEncoding("quoted-printable");
    att->header().contentDisposition("inline; filename=\"encrypted.asc\"");
    att->body().assign(crypto_result["data"].asString());
    att->body().push_back(NEWLINE);
  }

  char buf[16];
  snprintf(buf, 16, "%lu", time(NULL));
  boundary += buf;
  message->header().contentType().param("boundary", boundary);

  // Push the attachment into the MimeMultipart message
  message->body().parts().push_back(att);

  return message;
}

static size_t readcb(void *ptr, size_t size, size_t nmemb, void *stream) {
  readarg_t *rarg = (readarg_t *)stream;
  unsigned int len = rarg->body_size - rarg->body_pos;
  if (len > size * nmemb)
    len = size * nmemb;
  memcpy(ptr, rarg->data + rarg->body_pos, len);
  rarg->body_pos += len;
  printf("readcb: %d bytes\n", len);
  return len;
}

std::string pgpMimeToString(MimeEntity* pMe, const char* boundary = "") {
  std::stringstream messageString;
  messageString << *pMe;
  return messageString.str();
}

CURLcode sslContextCallback(CURL * curl, void * ctx, void * parm) {
    // Load CA certificates from memory
    CyaSSL_CTX_set_verify(reinterpret_cast<CYASSL_CTX*>(ctx),
                          SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0
    );

    int ret = CyaSSL_CTX_load_verify_buffer(reinterpret_cast<CYASSL_CTX*>(ctx),
                                            google_root_ca,
                                            (long)sizeof(google_root_ca),
                                            SSL_FILETYPE_ASN1);

    if (ret != SSL_SUCCESS) {
        if (ret == SSL_BAD_FILETYPE)
          std::cerr << "file is the wrong format" << std::endl;

        if (ret == SSL_BAD_FILE)
          std::cerr << "file doesn't exist, can't be read, or is corrupted." << std::endl;

        if (ret == MEMORY_E) {
          std::cerr << "out of memory condition occurs." << std::endl;
          return CURLE_OUT_OF_MEMORY;
        }

        if (ret == ASN_INPUT_E)
          std::cerr << "Base16 decoding fails on the file." << std::endl;

        if (ret == BUFFER_E)
          std::cerr << "chain buffer is bigger than the receiving buffer." << std::endl;

        return CURLE_SSL_CERTPROBLEM;
    }

    return CURLE_OK;
}

Json::Value webpg::sendMessage(const Json::Value& msgInfo) {
  Json::Value response(Json::objectValue);
  std::string host_url = msgInfo["host_url"].asString();
  std::string username = msgInfo["username"].asString();
  std::string bearer = msgInfo["bearer"].asString();
  Json::Value recipients_m = msgInfo["recipients"];
  std::string recip_from = recipients_m["from"].asString();
  Json::Value to_list = recipients_m["to"];
  Json::Value cc_list = recipients_m["cc"];
  Json::Value bcc_list = recipients_m["bcc"];
  Json::Value signers = msgInfo["signers"];
  std::string subject = msgInfo["subject"].asString();
  std::string msgBody = msgInfo["message"].asString();
  Json::Value attachments = msgInfo["attachments"];

  std::string mimeType = (msgInfo.isMember("mimeType") == true) ?
      msgInfo["mimeType"].asString() : "text/plain";

  int msgType = msgInfo["messagetype"].asInt();

  // Do some error checking
  // FIXME: Redundant and lots of returns
  if (host_url.length() < 1) {
    response["error"] = true;
    response["result"] = "Parameter \"host_url\" required. Aborting";
    return response;
  }
  if (username.length() < 1) {
    response["error"] = true;
    response["result"] = "Parameter \"username\" required. Aborting";
    return response;
  }
  if (bearer.length() < 1) {
    response["error"] = true;
    response["result"] = "Parameter \"bearer\" required. Aborting";
    return response;
  }
  if (recip_from.length() < 1) {
    response["error"] = true;
    response["result"] = "Parameter \"recipients\" must have \"from\" field. Aborting";
    return response;
  }
  if (to_list.size() < 1) {
    response["error"] = true;
    response["result"] = "Parameter \"recipients\" must have \"to\" list with at least one address. Aborting";
    return response;
  }

  MultipartMixed* me = createMessage(recipients_m,
    signers,
    msgType,
    subject,
    msgBody,
    attachments,
    mimeType
  );

  // Check if the recipient of this message is the runtime error address,
  //  which indicates that something went wrong.
  if (me->header().to().str() == "webpg-mime-runtime-error@webpg.org") {
    response["error"] = true;
    response["result"] = me->header().subject();
    return response;
  }

  std::string buffern = pgpMimeToString(me);

  readarg_t rarg;
  rarg.data = (char *) buffern.c_str();
  rarg.body_size = buffern.size();
  rarg.body_pos = 0;

  CURL *curl;
  CURLcode res;
  struct curl_slist *recipients = NULL;

  curl = curl_easy_init();
  if (curl) {
    curl_easy_setopt(curl, CURLOPT_URL, (char *) host_url.c_str());

    curl_easy_setopt(curl, CURLOPT_USE_SSL, (long) CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, *sslContextCallback);

    curl_easy_setopt(curl, CURLOPT_USERNAME, (char *) username.c_str());
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, (char *) bearer.c_str());

    // Envelope reverse-path
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, (char *) recip_from.c_str());

    // Iterate through the provided recipients (TO, CC and BCC)
    unsigned int nrecip;
    Json::Value lrecip;
    for (nrecip = 0; nrecip < to_list.size(); nrecip++) {
      lrecip = to_list[nrecip];
      recipients = curl_slist_append(recipients, (char *) lrecip.asCString());
    }
    for (nrecip = 0; nrecip < cc_list.size(); nrecip++) {
      lrecip = cc_list[nrecip];
      recipients = curl_slist_append(recipients, (char *) lrecip.asCString());
    }
    for (nrecip = 0; nrecip < bcc_list.size(); nrecip++) {
      lrecip = bcc_list[nrecip];
      recipients = curl_slist_append(recipients, (char *) lrecip.asCString());
    }
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    res = curl_easy_setopt(curl, CURLOPT_READFUNCTION, readcb);
    if(res != CURLE_OK) {
      response["error"] = true;
      response["result"] = curl_easy_strerror(res);
      return response;
    }

    res = curl_easy_setopt(curl, CURLOPT_READDATA, &rarg);
    if(res != CURLE_OK) {
      response["error"] = true;
      response["result"] = curl_easy_strerror(res);
      return response;
    }

#ifdef DEBUG
    #define DEBUG_CYASSL
    // debugging
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    CyaSSL_Debugging_ON();
#endif

    // Send the message (including headers)
    res = curl_easy_perform(curl);

    // Check for errors
    if(res != CURLE_OK) {
      response["error"] = true;
      response["result"] = curl_easy_strerror(res);
      return response;
    }

    // free the list of recipients and clean up
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
    response["error"] = false;
    response["result"] = "message sent";
  } else {
    response["error"] = true;
    response["result"] = "curl failed to initialized for unknown reasons";
  }

  return response;
}

Json::Value webpg::quotedPrintableDecode(const std::string& msg) {
  QP::Decoder qp;

  MimeEntity* plain;
  plain = new MimeEntity();

  plain->body().assign(msg.c_str());
  plain->body().code(qp);

  return plain->body();
}

Json::Value webpg::verifyPGPMimeMessage(const std::string& msg) {
  std::string::const_iterator bit = msg.begin(), eit = msg.end(), it;
  MimeEntity me(bit, eit);
  return pgpMimeToString(&me);
}

Json::Value webpg::checkForUpdate(const boost::optional<bool> force) {
  struct stat info;
  Json::Value res;
  res["error"] = true;
  res["update"] = false;

#ifdef HAVE_W32_SYSTEM
  char* path_separator = "\\";
#else
  char path_separator = '/';
#endif

  webpg::get_webpg_status();
  std::string path = webpg_status_map["plugin"]["path"].asString();
  path = path.substr(0, path.find_last_of("/\\")) + path_separator + "autoupdate";
  int filestat = stat(path.c_str(), &info);
  if (filestat == 0) {
    path += " --unattendedmodeui none --mode unattended --unattendedmodebehavior download";
    int update_res = system(path.c_str());
    update_res = WEXITSTATUS(update_res);
    if (update_res == 0) {
      res["error"] = false;
      res["update"] = true;
    } else if (update_res == 1) {
      res["error"] = false;
      res["update"] = false;
    } else if (update_res == 2)
      res["status"] = "Error connecting to remote server or invalid XML file";
    else if (update_res == 3)
      res["status"] = "An error occurred downloading the file";
    else if (update_res == 4)
      res["status"] = "An error occurred executing the downloaded update";
    else if (update_res == 5)
      res["status"] = "Update check disabled through check_for_updates setting";
    else
      res["status"] = "Unknown error";
    return res;
  }
  res["status"] = "autoupdate not installed";
  return res;
}

#ifdef H_LIBWEBPG // Do not include these methods when compiling the binary
// exported methods
webpg webpg;
extern "C" const char* webpg_version_r(EXTERN_FNC_CB callback) {
  fnOutputString = webpg.get_version().toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* webpg_status_r(EXTERN_FNC_CB callback) {
  fnOutputString = webpg.get_webpg_status().toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* getPublicKeyList_r(bool fast, bool async, STATUS_PROGRESS_CB callback) {
  Json::Value ret = webpg.getPublicKeyList(fast, async, callback);
  Json::FastWriter writer;
  fnOutputString = writer.write(ret);

  if (callback && !async) {
    callback(fnOutputString.c_str(), "onstatusprogress");
    return "{\"status\": \"queued\"}";
  }

  return fnOutputString.c_str();
}

extern "C" const char* getPrivateKeyList_r(bool fast, bool async, STATUS_PROGRESS_CB callback) {
  Json::Value ret = webpg.getPrivateKeyList(fast, async, callback);
  Json::FastWriter writer;
  fnOutputString = writer.write(ret);

  if (callback) {
    callback(fnOutputString.c_str(), "onstatusprogress");
    return "{\"status\": \"queued\"}";
  }

  return fnOutputString.c_str();
}

extern "C" const char* getNamedKey_r(const char* name, STATUS_PROGRESS_CB callback) {
  fnOutputString = webpg.getNamedKey(name).toStyledString();

  if (callback)
    callback(fnOutputString.c_str(), "onstatusprogress");

  return fnOutputString.c_str();
}

extern "C" const char* getExternalKey_r(const char* name,
                                        STATUS_PROGRESS_CB callback) {
  fnOutputString = webpg.getExternalKey(name).toStyledString();

  if (callback)
    callback(fnOutputString.c_str(), "onstatusprogress");

  return fnOutputString.c_str();
}

extern "C" const char* gpgSetPreference_r(const char* preference,
                                          const char* pref_value,
                                          EXTERN_FNC_CB callback) {
  fnOutputString = webpg.gpgSetPreference(preference, pref_value).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgGetPreference_r(const char* preference,
                                          EXTERN_FNC_CB callback) {
  fnOutputString = webpg.gpgGetPreference(preference).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgSetGroup_r(const char* group,
                                     const char* group_value,
                                     EXTERN_FNC_CB callback) {
  fnOutputString = webpg.gpgSetGroup(group, group_value).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* setTempGPGOption_r(const char* option,
                                          const char* value,
                                          EXTERN_FNC_CB callback) {
  fnOutputString = webpg.setTempGPGOption(option, value).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* restoreGPGConfig_r(EXTERN_FNC_CB callback) {
  fnOutputString = webpg.restoreGPGConfig().toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgSetHomeDir_r(const char* gnupg_path,
                                       EXTERN_FNC_CB callback) {
  fnOutputString = webpg.gpgSetHomeDir(gnupg_path).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgGetHomeDir_r(EXTERN_FNC_CB callback) {
  fnOutputString = webpg.gpgGetHomeDir().toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgSetBinary_r(const char* gnupg_exec,
                                       EXTERN_FNC_CB callback) {
  fnOutputString = webpg.gpgSetBinary(gnupg_exec).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgGetBinary_r(EXTERN_FNC_CB callback) {
  fnOutputString = webpg.gpgGetBinary().toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgSetGPGConf_r(const char* gpgconf_exec,
                                       EXTERN_FNC_CB callback) {
  fnOutputString = webpg.gpgSetGPGConf(gpgconf_exec).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgGetGPGConf_r(EXTERN_FNC_CB callback) {
  fnOutputString = webpg.gpgGetGPGConf().toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* getTemporaryPath_r(EXTERN_FNC_CB callback) {
  fnOutputString = webpg.getTemporaryPath().toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgEncrypt_r(const char* data,
                                    const char* enc_to_keyids[],
                                    int key_count,
                                    EXTERN_FNC_CB callback) {
  Json::Value _enc_to_keyids;

  for (int i=0; i < key_count + 1; i++)
    _enc_to_keyids.append(enc_to_keyids[i]);

  fnOutputString = webpg.gpgEncrypt(data,
                                    _enc_to_keyids,
                                    false,
                                    NULL).toStyledString();
  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgEncryptSign_r(const char* data,
                                        const char* enc_to_keyids[],
                                        int key_count,
                                        const char* signers[],
                                        int signer_count,
                                        EXTERN_FNC_CB callback) {
  Json::Value _enc_to_keyids, _signers;

  for (int i=0; i < key_count + 1; i++)
    _enc_to_keyids.append(enc_to_keyids[i]);

  for (int i=0; i < signer_count + 1; i++)
    _signers.append(signers[i]);

  fnOutputString = webpg.gpgEncrypt(data,
                                    _enc_to_keyids,
                                    true,
                                    _signers).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgSymmetricEnc_r(const char* data,
                                         bool sign,
                                         const char* signers[],
                                         int signer_count,
                                         EXTERN_FNC_CB callback) {
  Json::Value _signers;

  for (int i=0; i < signer_count + 1; i++)
    _signers.append(signers[i]);

  fnOutputString = webpg.gpgSymmetricEncrypt(data,
                                             sign,
                                            _signers).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgDecrypt_r(const char* data,
                                    EXTERN_FNC_CB callback) {

  fnOutputString = webpg.gpgDecrypt(data).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgVerify_r(const char* data,
                                   const char* plaintext,
                                   EXTERN_FNC_CB callback) {

  std::string pt;
  if (strlen (plaintext) > 1)
    pt = plaintext;

  fnOutputString = webpg.gpgVerify(data, pt).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgSignText_r(const char* data,
                                     const char* signers[],
                                     int key_count,
                                     int sign_mode,
                                     EXTERN_FNC_CB callback) {
  Json::Value _signers;

  for (int i=0; i < key_count + 1; i++)
    _signers.append(signers[i]);

  fnOutputString = webpg.gpgSignText(data,
                                    _signers,
                                    sign_mode).toStyledString();

  if (callback)
    callback(fnOutputString.c_str());

  return fnOutputString.c_str();
}

extern "C" const char* gpgGenSubKey_r(const char* keyid,
                                      const char* subkey_type,
                                      const char* subkey_length,
                                      const char* subkey_expire,
                                      bool sign_flag,
                                      bool enc_flag,
                                      bool auth_flag,
                                      GENKEY_PROGRESS_CB callback) {

  fnOutputString = webpg.gpgGenSubKey(keyid,
                                      subkey_type,
                                      subkey_length,
                                      subkey_expire,
                                      sign_flag,
                                      enc_flag,
                                      auth_flag,
                                      callback);

  return fnOutputString.c_str();
}
// end exported methods
#endif // H_LIBWEBPG

#ifndef H_LIBWEBPG // Do not include this method when compiling the lib
int main(int argc, char* argv[]) {
  webpg webpg;

  if (argv[1] != NULL) {
    std::string inp = argv[1];
    bool nativeHost = false;

    for (int i=1; i < argc; i++) {
        if (string(argv[i]).find("chrome-extension://") != std::string::npos) {
            nativeHost = true;
            break;
        }
    }

    unsigned int len = 0;
    // Define the "res" object which is output on stdout after function
    //  invocation.
    Json::Value res(Json::objectValue);

    // Check if this is being called as a native messaging host from chrome
    if (nativeHost == true) {
      WEBPG_PLUGIN_TYPE = WEBPG_PLUGIN_TYPE_NATIVEHOST;
      // Reset inp
      inp = "";

      std::cin.read((char*) &len, sizeof(len));

      char *str = new char[len];

      std::cout.sync_with_stdio(false);
      std::cin.sync_with_stdio(false);

      size_t frres = fread(str, sizeof(char), len, stdin);

      if (frres)
        inp += str;
    }

    // Create our objects to store the message in a usable format.
    Json::Value input_json;
    Json::Reader _action_reader;

    // Parse the message passed on stdin as a Json::Value
    bool parseResult = _action_reader.parse(inp, input_json);
    if (parseResult == false)
      res = _action_reader.getFormatedErrorMessages();

    // Check for the "func" member, which indicates a function is described.
    if (input_json.isMember("func") == true) {
      // Get the name of the function.
      std::string func = input_json["func"].asString();
      // Pack the parameters (if any) into the params Json::Value object.
      Json::Value params(Json::objectValue);
      params = input_json["params"];

      if (func == "get_version")
        res = webpg.get_version();
      else if (func == "get_webpg_status")
        res = webpg.get_webpg_status();
      else if (func == "getKeyCount")
        res = webpg.getKeyCount();
      else if (func == "getNamedKey")
        res = webpg.getNamedKey(
          params["name"].asString(),
          params["fastListMode"].asBool()
        );
      else if (func == "getPublicKeyList")
        res = webpg.getPublicKeyList(
          params["fastListMode"].asBool(),
          params["async"].asBool()
        );
      else if (func == "getPrivateKeyList")
        res = webpg.getPrivateKeyList(
          params["fastListMode"].asBool(),
          params["async"].asBool()
        );
      else if (func == "getExternalKey")
        res = webpg.getExternalKey(
          params["name"].asString()
        );
      else if (func == "gpgSetPreference")
        res = webpg.gpgSetPreference(params[0].asString(),
                                     params[1].asString());
      else if (func == "gpgGetPreference")
        res = webpg.gpgGetPreference(params[0].asString());
      else if (func == "gpgSetGroup")
        res = webpg.gpgSetGroup(params[0].asString(), params[1].asString());
      else if (func == "gpgSetHomeDir")
        res = webpg.gpgSetHomeDir(params[0].asString());
      else if (func == "gpgGetHomeDir")
        res = webpg.gpgGetHomeDir();
      else if (func == "gpgSetBinary")
        res = webpg.gpgSetBinary(params[0].asString());
      else if (func == "gpgGetBinary")
        res = webpg.gpgGetBinary();
      else if (func == "gpgSetGPGConf")
        res = webpg.gpgSetGPGConf(params[0].asString());
      else if (func == "gpgGetGPGConf")
        res = webpg.gpgGetGPGConf();
      else if (func == "gpgEncrypt")
        res = webpg.gpgEncrypt(params["text"].asString(),
                               params["recipients"],
                               params["sign"].asBool(),
                               params["signers"]);
      else if (func == "gpgSymmetricEncrypt")
        res = webpg.gpgSymmetricEncrypt(params["text"].asString(),
                                        params["sign"].asBool(),
                                        params["signers"]);
      else if (func == "gpgDecrypt")
        res = webpg.gpgDecrypt(params[0].asString());
      else if (func == "gpgVerify")
        res = webpg.gpgVerify(params["data"].asString(),
                              params["plaintext"].asString());
      else if (func == "gpgSignText")
        res = webpg.gpgSignText(params["text"].asString(),
                                params["signers"],
                                params["signType"].asInt());
      else if (func == "gpgSignUID")
        res = webpg.gpgSignUID(params[0].asString(),
                               params[1].asInt(),
                               params[2].asString(),
                               params[3].asInt(),
                               params[4].asInt(),
                               params[5].asInt(),
                               params[6].asString(),
                               params[7].asString());
      else if (func == "gpgDeleteUIDSign")
        res = webpg.gpgDeleteUIDSign(params[0].asString(),
                                     params[1].asInt(),
                                     params[2].asInt());
      else if (func == "gpgEnableKey")
        res = webpg.gpgEnableKey(params[0].asString());
      else if (func == "gpgDisableKey")
        res = webpg.gpgDisableKey(params[0].asString());
      else if (func == "gpgGenKey")
        res = webpg.gpgGenKey(params[0].asString(),
                              params[1].asString(),
                              params[2].asString(),
                              params[3].asString(),
                              params[4].asString(),
                              params[5].asString(),
                              params[6].asString(),
                              params[7].asString(),
                              params[8].asString(),
                              NULL);
      else if (func == "gpgGenSubKey")
        res = webpg.gpgGenSubKey(params[0].asString(),
                                 params[1].asString(),
                                 params[2].asString(),
                                 params[3].asString(),
                                 params[4].asBool(),
                                 params[5].asBool(),
                                 params[6].asBool(),
                                 NULL);
      else if (func == "gpgImportKey")
        res = webpg.gpgImportKey(params[0].asString());
      else if (func == "gpgImportExternalKey")
        res = webpg.gpgImportExternalKey(params[0].asString());
      else if (func == "gpgDeletePublicKey")
        res = webpg.gpgDeletePublicKey(params[0].asString());
      else if (func == "gpgDeletePrivateKey")
        res = webpg.gpgDeletePrivateKey(params[0].asString());
      else if (func == "gpgDeletePrivateSubKey")
        res = webpg.gpgDeletePrivateSubKey(params[0].asString(),
                                           params[1].asInt());
      else if (func == "gpgSetKeyTrust")
        res = webpg.gpgSetKeyTrust(params[0].asString(),
                                   params[1].asInt());
      else if (func == "gpgAddUID")
        res = webpg.gpgAddUID(params[0].asString(),
                              params[1].asString(),
                              params[2].asString(),
                              params[3].asString());
      else if (func == "gpgDeleteUID")
        res = webpg.gpgDeleteUID(params[0].asString(), params[1].asInt());
      else if (func == "gpgSetPrimaryUID")
        res = webpg.gpgSetPrimaryUID(params[0].asString(),
                                     params[1].asInt());
      else if (func == "gpgSetSubkeyExpire")
        res = webpg.gpgSetSubkeyExpire(params[0].asString(),
                                       params[1].asInt(),
                                       params[2].asInt());
      else if (func == "gpgSetPubkeyExpire")
        res = webpg.gpgSetPubkeyExpire(params[0].asString(),
                                       params[1].asInt());
      else if (func == "gpgExportPublicKey")
        res = webpg.gpgExportPublicKey(params[0].asString());
      else if (func == "gpgPublishPublicKey")
        res = webpg.gpgPublishPublicKey(params[0].asString());
      else if (func == "gpgRevokeKey")
        res = webpg.gpgRevokeKey(params[0].asString(),
                                 params[1].asInt(),
                                 params[2].asInt(),
                                 params[3].asString());
      else if (func == "gpgRevokeUID")
        res = webpg.gpgRevokeUID(params[0].asString(),
                                 params[1].asInt(),
                                 params[2].asInt(),
                                 params[3].asString());
      else if (func == "gpgRevokeSignature")
        res = webpg.gpgRevokeSignature(params[0].asString(),
                                       params[1].asInt(),
                                       params[2].asInt(),
                                       params[3].asInt(),
                                       params[4].asString());
      else if (func == "gpgChangePassphrase")
        res = webpg.gpgChangePassphrase(params[0].asString());
      else if (func == "gpgShowPhoto")
        webpg.gpgShowPhoto(params[0].asString());
      else if (func == "gpgAddPhoto")
        res = webpg.gpgAddPhoto(params[0].asString(),
                                params[1].asString(),
                                params[2].asString());
      else if (func == "gpgGetPhotoInfo")
        res = webpg.gpgGetPhotoInfo(params[0].asString());
      else if (func == "showPhotoCallback") {
        res = webpg.showPhotoCallback(params["keyid"].asString(),
                                      params["path"].asString(),
                                      params["extension"].asString(),
                                      params["index"].asInt(),
                                      params["count"].asInt());
      } else if (func == "setTempGPGOption")
        res = webpg.setTempGPGOption(params["option"].asString(),
                                     params["value"].asString());
      else if (func == "restoreGPGConfig")
        res = webpg.restoreGPGConfig();
      else if (func == "getTemporaryPath")
        res = webpg.getTemporaryPath();
      else if (func == "sendMessage")
        res = webpg.sendMessage(params);
      else if (func == "quotedPrintableDecode")
        res = webpg.quotedPrintableDecode(params[0].asString());
      else if (func == "verifyPGPMimeMessage")
        res = webpg.verifyPGPMimeMessage(params[0].asString());
      else if (func == "checkForUpdate")
        res = webpg.checkForUpdate(params[0].asBool());
      else
        res = get_error_map(__func__,
                            GPG_ERR_UNKNOWN_COMMAND,
                            __LINE__,
                            __FILE__);
    }

    writeOut(res, parseResult);
  }

  return 0;
}
#endif // H_LIBWEBPG
