/**********************************************************\ 
Original Author: Kyle L. Huff (kylehuff)

Created:    Jan 14, 2011
License:    GNU General Public License, version 2
            http://www.gnu.org/licenses/gpl-2.0.html

Copyright 2013 Kyle L. Huff, CURETHEITCH development team
\**********************************************************/
#include <sstream>
#include <iostream>
#include <fstream>
#include <cerrno>
#include <assert.h>
#include <string.h>

#define BOOST_THREAD_USE_LIB
// BOOST includes
#include <boost/optional.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/remove_whitespace.hpp>

#include <gpgme.h>
#include "libs/jsoncpp/include/json/json.h"

#include <mimetic/mimetic.h>
#include <mimetic/streambufs.h>
#include <curl.h>

#ifdef HAVE_W32_SYSTEM
#include <windows.h>
#include <tchar.h>
#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef int ssize_t;
#endif
#endif

#define WEBPG_PLUGIN_TYPE_CLI         1
#define WEBPG_PLUGIN_TYPE_LIB         2
#define WEBPG_PLUGIN_TYPE_NPAPI       3
#define WEBPG_PLUGIN_TYPE_NATIVEHOST  4

#define WEBPG_VERSION_MAJOR           0
#define WEBPG_VERSION_MINOR           8
#define WEBPG_VERSION_STRING          "0.8"
#define WEBPG_PGPMIME_ENCRYPTED       1
#define WEBPG_PGPMIME_SIGNED          2
#define WEBPG_MIME_VERSION_MAJOR      1
#define WEBPG_MIME_VERSION_MINOR      0
#define WEBPG_MIME_VERSION_STRING     "1.0"
#define NEWLINE                       '\n'

typedef struct {
  char *data;
  int body_size;
  int body_pos;
} readarg_t;

// remove?
typedef char* (*TYPE_webpg)(void);

// Used for allowing caller to assign a callback method
typedef void (*EXTERN_FNC_CB)(const char*);
typedef void (*GENKEY_PROGRESS_CB)(const char*, const char*);
typedef void (*STATUS_PROGRESS_CB)(const char*, const char*);
typedef void (*STATUS_CB)(void*, const char*);
typedef void (*pluginAPI)(void*);

typedef struct {
  std::string key_type;
  std::string key_length;
  std::string subkey_type;
  std::string subkey_length;
  std::string name_real;
  std::string name_comment;
  std::string name_email;
  std::string expire_date;
  std::string passphrase;
} genKeyParams;

typedef struct {
  std::string keyid;
  std::string subkey_type;
  std::string subkey_length;
  std::string subkey_expire;
  bool sign_flag;
  bool enc_flag;
  bool auth_flag;
} genSubKeyParams;

typedef enum {
  WEBPG_EDIT_NONE,
  WEBPG_EDIT_SIGN,
  WEBPG_EDIT_DELSIGN,
  WEBPG_EDIT_ENABLE,
  WEBPG_EDIT_DISABLE,
  WEBPG_EDIT_ADDSUBKEY,
  WEBPG_EDIT_DELSUBKEY,
  WEBPG_EDIT_ADD_UID,
  WEBPG_EDIT_DEL_UID,
  WEBPG_EDIT_SET_PRIMARY_UID,
  WEBPG_EDIT_SET_KEY_EXPIRE,
  WEBPG_EDIT_REVOKE_ITEM,
  WEBPG_EDIT_PASSPHRASE,
  WEBPG_EDIT_ASSIGN_TRUST,
  WEBPG_EDIT_SHOW_PHOTO,
  WEBPG_EDIT_CHECK_PHOTO,
  WEBPG_EDIT_ADD_PHOTO
} WEBPG_EDIT_TYPES;

///////////////////////////////////////////////////////////////////////////////
/// @class  webpg
///
/// @brief  Main WebPG Class
///////////////////////////////////////////////////////////////////////////////
class webpg {
  public:
//    webpg();
//    virtual ~webpg();
    pluginAPI* plugin;

    Json::Value webpg_status_map;

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value get_webpg_status()
    ///
    /// @brief  Executes init() to set the status variables and
    ///         populates the "edit_status" property with the contents of the
    ///         edit_status constant.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value get_webpg_status();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn void init()
    ///
    /// @brief  Initializes the webpgPlugin and sets the status variables.
    ///////////////////////////////////////////////////////////////////////////
    void init();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn gpgme_ctx_t get_gpgme_ctx()
    ///
    /// @brief  Creates the gpgme context with the required options.
    ///////////////////////////////////////////////////////////////////////////
    gpgme_ctx_t get_gpgme_ctx();

    void FireEvent(const char* event, Json::Value type);

    Json::Value getKeyCount();

    Json::Value getKeyListWorker(
      const std::string& name,
      bool secret_only,
      bool fast,
      void* APIObj,
      void(*cb_status)(
        void *self,
        const char *msg
      )
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value getKeyList(cont std::string& name, bool secret_only)
    ///
    /// @brief  Retrieves all keys matching name, or if name is not specified,
    ///         returns all keys in the keyring. The keyring to use is determined
    ///         by the integer value of secret_only.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value getKeyList(
      const std::string& name,
      bool secret_only,
      bool fast,
      void* APIObj,
      void(*cb_status)(
        void *self,
        const char *msg
      )
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value getNamedKey(const std::string& name)
    ///
    /// @brief  Calls getKeyList() with a search string and the
    ///         secret_only paramter as false, which returns only Public Keys
    ///         from the keyring. 
    ///////////////////////////////////////////////////////////////////////////
    Json::Value getNamedKey(
      const std::string& name,
      const boost::optional<bool> fast
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value getExternalKey(const std::string& name)
    ///
    /// @brief  Calls getKeyList() after setting the context to 
    ///         external mode with a search string and the secret_only paramter as
    ///         false, which returns only Public Keys
    ///////////////////////////////////////////////////////////////////////////
    Json::Value getExternalKey(const std::string& name);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value getPublicKeyList()
    ///
    /// @brief  Calls getKeyList() without specifying a search
    ///         string, and the secret_only paramter as false, which returns only
    ///         Public Keys from the keyring. 
    ///////////////////////////////////////////////////////////////////////////
    Json::Value getPublicKeyList(
      bool fastListMode=false,
      bool async=false,
      STATUS_PROGRESS_CB callback=NULL
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value getPrivateKeyList()
    ///
    /// @brief  Calls getKeyList() without specifying a search
    ///         string, and the secret_only paramter as true, which returns only
    ///         Private Keys from the keyring. 
    ///////////////////////////////////////////////////////////////////////////
    Json::Value getPrivateKeyList(
      bool fastListMode=false,
      bool async=false,
      STATUS_PROGRESS_CB callback=NULL
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn std::string get_preference(const std::string& preference)
    ///
    /// @brief  Attempts to retrieve the specified preference from the gpgconf
    ///         utility.
    ///
    /// @param  preference  The gpgconf preference to retrieve.
    ///////////////////////////////////////////////////////////////////////////
    std::string get_preference(const std::string& preference);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSetPreference(const std::string& preference,
    ///                                  const std::string& pref_value)
    ///
    /// @brief  Attempts to set the specified gpgconf preference with the value
    ///         of pref_value.
    ///
    /// @param  preference  The preference to set.
    /// @param  pref_value  The value to assign to the specified preference. 
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSetPreference(
      const std::string& preference,
      const std::string& pref_value
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSetGroup(const std::string& group,
    ///                             const std::string& group_value)
    ///
    /// @brief  Attempts to define or clear the specified group preference with the value
    ///         of group_value.
    ///
    /// @param  group  The group to set.
    /// @param  group_value  The value to assign to the specified group. 
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSetGroup(
      const std::string& group,
      const std::string& group_value
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn std::string gpgGetPreference(const std::string& preference)
    ///
    /// @brief  Attempts to retrieve the specified preference from the gpgconf
    ///         utility.
    ///
    /// @param  preference  The gpgconf preference to retrieve.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgGetPreference(const std::string& preference);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn std::string getGPGConfigFilename()
    ///
    /// @brief  Attempts to determine the correct location of the gpg
    ///         configuration file.
    ///////////////////////////////////////////////////////////////////////////
    std::string getGPGConfigFilename();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value setTempGPGOption(const std::string& option,
    ///                                  const std::string& value)
    ///
    /// @brief  Creates a backup of the gpg.conf file and writes the options to
    ///         gpg.conf; This should be called prior to initializing the
    ///         gpgme context.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value setTempGPGOption(
      const std::string& option,
      const std::string& value
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value restoreGPGConfig()
    ///
    /// @brief  Restores the gpg.conf file from memory or the backup file.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value restoreGPGConfig();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSetHomeDir(const std::string& gnupg_path)
    ///
    /// @brief  Sets the GNUPGHOME static variable to the path specified in 
    ///         gnupg_path. This should be called prior to initializing the
    ///         gpgme context.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSetHomeDir(const std::string& gnupg_path);
    Json::Value gpgGetHomeDir();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSetBinary(const std::string& gnupg_exec)
    ///
    /// @brief  Sets the GNUPGBIN static variable to the path specified in 
    ///         gnupg_exec. This should be called prior to initializing the
    ///         gpgme context.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSetBinary(const std::string& gnupg_exec);
    Json::Value gpgGetBinary();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSetGPGConf(const std::string& gpgconf_exec)
    ///
    /// @brief  Sets the GPGCONF static variable to the path specified in 
    ///         gpgconf_exec.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSetGPGConf(const std::string& gpgconf_exec);
    Json::Value gpgGetGPGConf();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value getTemporaryPath()
    ///
    /// @brief  Attempts to determine the system or user temporary path.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value getTemporaryPath();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgEncrypt(const std::string& data,
    ///                            const Json::Value& enc_to_keyids, bool sign)
    ///
    /// @brief  Encrypts the data passed in data with the key ids passed in
    ///         enc_to_keyids and optionally signs the data.
    ///
    /// @param  data    The data to encrypt.
    /// @param  enc_to_keyids   An array of key ids to encrypt to (recpients).
    /// @param  sign    The data should be also be signed.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgEncrypt(
      const std::string& data,
      const Json::Value& enc_to_keyids,
      const boost::optional<bool>& sign,
      const boost::optional<Json::Value>& opt_signers
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSymmetricEncrypt(const std::string& data, bool sign)
    ///
    /// @brief  Calls gpgEncrypt() without any recipients specified which
    ///         initiates a Symmetric encryption method on the gpgme context.
    ///
    /// @param  data    The data to symmetrically encrypt.
    /// @param  sign    The data should also be signed. NOTE: Signed symmetric
    ///                 encryption does not work in gpgme > v1.4.2; For details
    ///                 see https://bugs.g10code.com/gnupg/issue1440
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSymmetricEncrypt(
      const std::string& data,
      const boost::optional<bool>& sign,
      const boost::optional<Json::Value>& opt_signers
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgDecryptVerify(const std::string& data,
    ///                                  const std::string& plaintext,
    ///                                  int use_agent)
    ///
    /// @brief  Attempts to decrypt and verify the string data. If use_agent
    ///         is 0, it will attempt to disable the key-agent to prevent the
    ///         passphrase dialog from displaying. This is useful in cases
    ///         where you want to verify or decrypt without unlocking the
    ///         private keyring (i.e. in an automated parsing environment).
    ///
    /// @param  data    The data to decrypt and/or verify.
    /// @param  plaintext   The plaintext of a detached signature.
    /// @param  use_agent   Attempt to disable the gpg-agent.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgDecryptVerify(
      const std::string& data,
      const std::string& plaintext,
      int use_agent
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgDecrypt(const std::string& data)
    ///
    /// @brief  Calls gpgDecryptVerify() with the use_agent flag
    ///         specifying to not disable the gpg-agent.
    ///
    /// @param  data    The data to decyrpt.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgDecrypt(const std::string& data);

    Json::Value gpgVerify(
      const std::string& data,
      const boost::optional<std::string>& plaintext
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSignText(const std::string& plain_text,
    ///                             Json::Value& signers,
    ///                             int sign_mode)
    ///
    /// @brief  Signs the text specified in plain_text with the key ids 
    ///         specified in <signers>, with the signature mode specified in
    ///         <sign_mode>.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSignText(
      const std::string& plain_text,
      const Json::Value& signers,
      const boost::optional<int>& opt_sign_mode
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSignUID(const std::string& keyid,
    ///                            long sign_uid,
    ///                            const std::string& with_keyid,
    ///                            long local_only,
    ///                            long trust_sign,
    ///                            long trust_level)
    ///
    /// @brief  Signs the UID index of the specified key id using the signing
    ///         key specified by <with_keyid>.
    ///
    /// @param  keyid       The ID of the key with the desired UID to sign.
    /// @param  sign_uid    The 0 based index of the UID.
    /// @param  with_keyid  The ID of the key to create the signature with.
    /// @param  local_only  Specifies if the signature is non exportable.
    /// @param  trust_sign  Specifies if this is a trust signature.
    /// @param  trust_level The level of trust to assign.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSignUID(
      const std::string& keyid,
      long uid,
      const std::string& with_keyid,
      long local_only,
      long trust_sign,
      long trust_level,
      const boost::optional<std::string>& notation_name,
      const boost::optional<std::string>& notation_value
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgDeleteUIDSign(const std::string& keyid,
    ///                                  long uid,
    ///                                  long signature)
    ///
    /// @brief  Deletes the Signature signature on the uid of keyid.
    ///
    /// @param  keyid     The ID of the key.
    /// @param  uid       The index of the UID containing the signature.
    /// @param  signature The index of signature to delete.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgDeleteUIDSign(
      const std::string& keyid,
      long sign_uid,
      long signature
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgEnableKey(const std::string& keyid)
    ///
    /// @brief  Sets the key specified with keyid as enabled in gpupg. 
    ///
    /// @param  keyid    The ID of the key to enable.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgEnableKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgDisableKey(const std::string& keyid)
    ///
    /// @brief  Sets the key specified with keyid as disabled in gpupg. 
    ///
    /// @param  keyid   The ID of the key to disable.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgDisableKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn std::string gpgGenKey(const std::string& key_type,
    ///                           const std::string& key_length,
    ///                           const std::string& subkey_type,
    ///                           const std::string& subkey_length,
    ///                           const std::string& name_real, 
    ///                           const std::string& name_comment,
    ///                           const std::string& name_email,
    ///                           const std::string& expire_date, 
    ///                           const std::string& passphrase)
    ///
    /// @brief  Queues a threaded gpg genkey operation.
    ///
    /// @param  key_type      The key type to genereate.
    /// @param  key_length    The size of the key to generate.
    /// @param  subkey_type   The subkey type to generate.
    /// @param  subkey_length The size of the subkey to genereate.
    /// @param  name_real     The name to assign to the UID.
    /// @param  name_comment  The comment to assign to the UID.
    /// @param  name_email    The email address to assign to the UID.
    /// @param  expire_date   The expiration date to assign to the key.
    /// @param  passphrase    The passphrase to assign the to the key.
    ///////////////////////////////////////////////////////////////////////////
    std::string gpgGenKey(
      const std::string& key_type,
      const std::string& key_length,
      const std::string& subkey_type,
      const std::string& subkey_length,
      const std::string& name_real,
      const std::string& name_comment,
      const std::string& name_email,
      const std::string& expire_date,
      const std::string& passphrase,
      GENKEY_PROGRESS_CB callback=NULL
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn std::string gpgGenSubKey(const std::string& keyid, 
    ///         const std::string& subkey_type, const std::string& subkey_length,
    ///         const std::string& subkey_expire, bool sign_flag, bool enc_flag, bool auth_flag) 
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
    ///////////////////////////////////////////////////////////////////////////
    std::string gpgGenSubKey(
      const std::string& keyid,
      const std::string& subkey_type,
      const std::string& subkey_length,
      const std::string& subkey_expire,
      bool sign_flag,
      bool enc_flag,
      bool auth_flag,
      GENKEY_PROGRESS_CB callback=NULL
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgImportKey(const std::string& ascii_key)
    ///
    /// @brief  Imports the ASCII encoded key ascii_key
    ///
    /// @param  ascii_key   An armored, ascii encoded PGP Key block.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgImportKey(const std::string& ascii_key);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgImportExternalKey(const std::string& ascii_key)
    ///
    /// @brief  Imports the ASCII encoded key ascii_key
    ///
    /// @param  ascii_key   An armored, ascii encoded PGP Key block.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgImportExternalKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgDeleteKey(const std::string& keyid,
    ///                              int allow_secret)
    ///
    /// @brief  Deletes the key specified in keyid from the keyring.
    ///
    /// @param  keyid         The ID of the key to delete.
    /// @param  allow_secret  Enables deleting a key from the private keyring.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgDeleteKey(const std::string& keyid, int allow_secret);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgDeletePublicKey(const std::string& keyid)
    ///
    /// @brief  Deletes key specified in keyid from the Public keyring.
    ///
    /// @param  keyid   The ID of the key to delete from the Public keyring.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgDeletePublicKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgDeletePrivateKey(const std::string& keyid)
    ///
    /// @brief  Deletes key specified in keyid from the Private keyring.
    ///
    /// @param  keyid   The ID of the key to delete from the Private keyring.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgDeletePrivateKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgDeletePrivateSubKey(const std::string& keyid,
    ///                                        int key_idx)
    ///
    /// @brief  Deletes the subkey located at index <key_idx> form the key
    ///         specified in <keyid>.
    ///
    /// @param  keyid   The ID of the key to delete the subkey from.
    /// @param  key_idx The index of the subkey to delete.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgDeletePrivateSubKey(const std::string& keyid, int key_idx);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSetKeyTrust(const std::string& keyid,
    ///                                long trust_level)
    ///
    /// @brief  Sets the gnupg trust level assignment for the given keyid.
    ///
    /// @param  keyid   The ID of the key to assign the trust level on.
    /// @param  trust_level The level of trust to assign.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSetKeyTrust(const std::string& keyid, long trust_level);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgAddUID(const std::string& keyid,
    ///                           const std::string& name,
    ///                           const std::string& email,
    ///                           const std::string& comment)
    ///
    /// @brief  Adds a new UID to the key specified by keyid
    ///
    /// @param  keyid   The ID of the key to add the UID to.
    /// @param  name    The name to assign to the new UID.
    /// @param  email   The email address to assign to the new UID.
    /// @param  comment The comment to assign to the new UID.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgAddUID(
        const std::string& keyid,
        const std::string& name,
        const std::string& email,
        const std::string& comment
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgDeleteUID(const std::string& keyid, long uid_idx)
    ///
    /// @brief  Deletes the UID specified by <uid_idx> from the key specified
    ///         with <keyid>.
    ///
    /// @param  keyid   The ID of the key to delete to the specified UID from.
    /// @param  uid_idx The index of the UID to delete from the key.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgDeleteUID(const std::string& keyid, long uid_idx);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSetPrimaryUID(const std::string& keyid,
    ///                                  long uid_idx)
    ///
    /// @brief  Sets a given UID as the primary for the key specified with
    ///         <keyid>.
    ///
    /// @param  keyid   The ID of the key with the UID to make primary.
    /// @param  uid_idx The index of the UID to make primary on the key.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSetPrimaryUID(const std::string& keyid, long uid_idx);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSetKeyExpire(const std::string& keyid,
    ///                                 long key_idx,
    ///                                 long expire)
    ///
    /// @brief  Sets the expiration of the given <key_idx> on the key specified
    ///         by <keyid> with the expiration of <expire>.
    ///
    /// @param  keyid   The ID of the key to set the expiration on.
    /// @param  key_idx The index of the subkey to set the expiration on.
    /// @param  expire  The expiration to assign.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSetKeyExpire(const std::string& keyid, long key_idx,
        long expire);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSetPubkeyExpire(const std::string& keyid,
    ///                                    long expire)
    ///
    /// @brief  Sets the expiration of the public key of the given <keyid>.
    ///
    /// @param  keyid   The ID of the key to set the expiration on.
    /// @param  expire  The expiration to assign to the key.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSetPubkeyExpire(const std::string& keyid, long expire);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgSetSubkeyExpire(const std::string& keyid,
    ///                                    long key_idx,
    ///                                    long expire)
    ///
    /// @brief  Sets the expiration of the subkey specified with <key_idx> on
    ///         the key specified with <keyid>.
    ///
    /// @param  keyid   The ID of the key to set the expiration on.
    /// @param  key_idx The index of the subkey to set the expiration on.
    /// @param  expire  The expiration to assign to the key.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgSetSubkeyExpire(
      const std::string& keyid,
      long key_idx,
      long expire
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgExportPublicKey(const std::string& keyid)
    ///
    /// @brief  Exports the public key specified with <keyid> as an ASCII
    ///         armored encoded PGP Block.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgExportPublicKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgPublishPublicKey(const std::string& keyid)
    ///
    /// @brief  Exports the key specified by <keyid> to the current keyserver
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgPublishPublicKey(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgRevokeItem(const std::string& keyid,
    ///                               const std::string& item,
    ///                               int key_idx,
    ///                               int uid_idx,
    ///                               int sig_idx,
    ///                               int reason,
    ///                               const std::string& desc)
    ///
    /// @brief  Revokes a given key, trust item, subkey, uid or signature with
    ///         the specified reason and description.
    ///
    /// @param  keyid   The ID of the key that contains the subitem passed.
    /// @param  item    The item to revoke.
    /// @param  key_idx The index of the subkey to revoke.
    /// @param  uid_idx The index of the UID to revoke.
    /// @param  sig_idx The index of the signature to revoke.
    /// @param  reason  The gnupg reason for the revocation.
    /// @param  desc    The text description for the revocation.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgRevokeItem(
      const std::string& keyid,
      const std::string& item,
      int key_idx,
      int uid_idx,
      int sig_idx,
      int reason_idx,
      const std::string& desc
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgRevokeKey(const std::string& keyid,
    ///                              int key_idx,
    ///                              int reason,
    ///                              const std::string &desc)
    ///
    /// @brief  Revokes the given key/subkey with the reason and description
    ///         specified.
    ///
    /// @param  keyid   The ID of the key to revoke.
    /// @param  key_idx The index of the subkey to revoke.
    /// @param  reason  The gnupg reason for the revocation.
    /// @param  desc    The text description for the revocation.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgRevokeKey(
      const std::string& keyid,
      int key_idx, int reason,
      const std::string &desc
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgRevokeUID(const std::string& keyid,
    ///                              int uid_idx,
    ///                              int reason,
    ///                              const std::string &desc)
    ///
    /// @brief  Revokes the given UID with the reason and description
    ///         specified.
    ///
    /// @param  keyid   The ID of the key with the UID to revoke.
    /// @param  uid_idx The index of the UID to revoke.
    /// @param  reason  The gnupg reason for the revocation.
    /// @param  desc    The text description for the revocation.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgRevokeUID(
        const std::string& keyid,
        int uid_idx,
        int reason,
        const std::string &desc
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgRevokeSignature(const std::string& keyid,
    ///                                    int uid_idx,
    ///                                    int sig_idx,
    ///                                    int reason,
    ///                                    const std::string &desc)
    ///
    /// @brief  Revokes the given signature on the specified UID of key keyid
    ///         with the reason and description specified.
    ///
    /// @param  keyid   The ID of the key with the signature to revoke.
    /// @param  uid_idx The index of the UID with the signature to revoke.
    /// @param  sig_idx The index of the signature to revoke.
    /// @param  reason  The gnupg reason for the revocation.
    /// @param  desc    The text description for the revocation.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgRevokeSignature(
      const std::string& keyid,
      int uid_idx,
      int sig_idx,
      int reason,
      const std::string &desc
    );

    ///////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgChangePassphrase(const std::string& keyid)
    ///
    /// @brief  Invokes the gpg-agent to change the passphrase for the given
    ///         key specified by <keyid>.
    ///
    /// @param  keyid   The ID of the key to change the passphrase.
    ///////////////////////////////////////////////////////////////////////////
    Json::Value gpgChangePassphrase(const std::string& keyid);

    int verifyDomainKey(
      const std::string& domain, 
      const std::string& domain_key_fpr,
      long uid_idx,
      const std::string& required_sig_keyid
    );

    void gpgShowPhoto(const std::string& keyid);

    Json::Value gpgAddPhoto(
      const std::string& keyid,
      const std::string& photo_name,
      const std::string& photo_data
    );

    Json::Value gpgGetPhotoInfo(const std::string& keyid);

    ///////////////////////////////////////////////////////////////////////////
    /// @fn std::string get_version()
    ///
    /// @brief  Retruns the defined plugin version
    ///////////////////////////////////////////////////////////////////////////
    Json::Value get_version();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn bool openpgp_detected()
    ///
    /// @brief  Determines if OpenPGP is available as a valid engine.
    ///////////////////////////////////////////////////////////////////////////
    bool openpgp_detected();

    ///////////////////////////////////////////////////////////////////////////
    /// @fn bool gpgconf_detected()
    ///
    /// @brief  Determines if gpgconf is available to the engine.
    ///////////////////////////////////////////////////////////////////////////
    bool gpgconf_detected();

    std::string original_gpg_config;

    ///////////////////////////////////////////////////////////////////////////
    /// @fn void genkey_progress_cb(void *self,
    ///                      const char *what,
    ///                      int type,
    ///                      int current,
    ///                      int total)
    ///
    /// @brief  Called by the long-running, asymmetric gpg genkey method to
    ///         display the status.
    ///
    /// @param  self    A reference to webpgPluginAPI, since the method is called
    ///                 outside of the class.
    /// @param  what    The current action status from gpg genkey.
    /// @param  type    The type of of action.
    /// @param  current ?
    /// @param  total   ?
    ///////////////////////////////////////////////////////////////////////////
    static void genkey_progress_cb(
      void *self,
      const char *what,
      int type,
      int current,
      int total
    );

    static void status_progress_cb(
      void *self,
      const char *msg
    );

//    gpgme_error_t passdefunct_cb(
//        void *self, const char *uid_hint,
//        const char *passphrase_info, int prev_was_bad, int fd
//    );

    ///////////////////////////////////////////////////////////////////////////////
    /// @fn std::string gpgGenKeyWorker(genKeyParams& params, void* APIObj,
    ///        void(*cb_status)(
    ///            void *self,
    ///            const char *what,
    ///            int type,
    ///            int current,
    ///            int total
    ///        ))
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
    /// @param  APIObj  A reference to webpgPluginAPI.
    /// @param  cb_status   The progress callback for the operation.
    ///////////////////////////////////////////////////////////////////////////////
    std::string gpgGenKeyWorker(genKeyParams& params,
        void* APIObj, void(*cb_status)(void *self,
            const char *what,
            int type,
            int current,
            int total
        )
    );

    ///////////////////////////////////////////////////////////////////////////////
    /// @fn Json::Value gpgGenSubKeyWorker(genSubKeyParams params, void* APIObj,
    ///         void(*cb_status)(
    ///            void *self,
    ///            const char *what,
    ///            int type,
    ///            int current,
    ///            int total
    ///         ))
    ///
    /// @brief  Creates a threaded worker to run the gpg keygen operation.
    ///
    /// @param  subkey_type    The subkey type to genereate.
    /// @param  subkey_length    The size of the subkey to generate.
    /// @param  subkey_expire The expiration date to assign to the generated key.
    /// @param  sign_flag  Set the sign capabilities flag.
    /// @param  enc_flag    Set the encrypt capabilities flag.
    /// @param  APIObj  A reference to webpgPluginAPI.
    /// @param  cb_status   The progress callback for the operation.
    ///////////////////////////////////////////////////////////////////////////////
    Json::Value gpgGenSubKeyWorker(genSubKeyParams params,
        void* APIObj, void(*cb_status)(void *self,
            const char *what,
            int type,
            int current,
            int total
        )
    );

    Json::Value sendMessage(const Json::Value& msgInfo);
    Json::Value quotedPrintableDecode(const std::string& msg);
    Json::Value verifyPGPMimeMessage(const std::string& msg);

private:
  // Private constructs
  mimetic::MultipartMixed* createMessage(
      const Json::Value& recipients_m,
      const Json::Value& signers,
      int messageType, // Signed, Encrypted
      const std::string& subject,
      const std::string& msgBody,
      const boost::optional<std::string>& mimeType
  );

};
