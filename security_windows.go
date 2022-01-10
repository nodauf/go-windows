// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package winsyscall

import (
	"unsafe"
)

const (
	NameUnknown          = 0
	NameFullyQualifiedDN = 1
	NameSamCompatible    = 2
	NameDisplay          = 3
	NameUniqueId         = 6
	NameCanonical        = 7
	NameUserPrincipal    = 8
	NameCanonicalEx      = 9
	NameServicePrincipal = 10
	NameDnsDomain        = 12
)

const (
	// do not reorder
	NetSetupUnknownStatus = iota
	NetSetupUnjoined
	NetSetupWorkgroupName
	NetSetupDomainName
)

type UserInfo10 struct {
	Name       *uint16
	Comment    *uint16
	UsrComment *uint16
	FullName   *uint16
}

//sys	NetUserGetInfo(serverName *uint16, userName *uint16, level uint32, buf **byte) (neterr error) = netapi32.NetUserGetInfo
//sys	NetGetJoinInformation(server *uint16, name **uint16, bufType *uint32) (neterr error) = netapi32.NetGetJoinInformation
//sys	NetApiBufferFree(buf *byte) (neterr error) = netapi32.NetApiBufferFree

const (
	// do not reorder
	SidTypeUser = 1 + iota
	SidTypeGroup
	SidTypeDomain
	SidTypeAlias
	SidTypeWellKnownGroup
	SidTypeDeletedAccount
	SidTypeInvalid
	SidTypeUnknown
	SidTypeComputer
	SidTypeLabel
)

type SidIdentifierAuthority struct {
	Value [6]byte
}

var (
	SECURITY_NULL_SID_AUTHORITY        = SidIdentifierAuthority{[6]byte{0, 0, 0, 0, 0, 0}}
	SECURITY_WORLD_SID_AUTHORITY       = SidIdentifierAuthority{[6]byte{0, 0, 0, 0, 0, 1}}
	SECURITY_LOCAL_SID_AUTHORITY       = SidIdentifierAuthority{[6]byte{0, 0, 0, 0, 0, 2}}
	SECURITY_CREATOR_SID_AUTHORITY     = SidIdentifierAuthority{[6]byte{0, 0, 0, 0, 0, 3}}
	SECURITY_NON_UNIQUE_AUTHORITY      = SidIdentifierAuthority{[6]byte{0, 0, 0, 0, 0, 4}}
	SECURITY_NT_AUTHORITY              = SidIdentifierAuthority{[6]byte{0, 0, 0, 0, 0, 5}}
	SECURITY_MANDATORY_LABEL_AUTHORITY = SidIdentifierAuthority{[6]byte{0, 0, 0, 0, 0, 16}}
)

const (
	SECURITY_NULL_RID                   = 0
	SECURITY_WORLD_RID                  = 0
	SECURITY_LOCAL_RID                  = 0
	SECURITY_CREATOR_OWNER_RID          = 0
	SECURITY_CREATOR_GROUP_RID          = 1
	SECURITY_DIALUP_RID                 = 1
	SECURITY_NETWORK_RID                = 2
	SECURITY_BATCH_RID                  = 3
	SECURITY_INTERACTIVE_RID            = 4
	SECURITY_LOGON_IDS_RID              = 5
	SECURITY_SERVICE_RID                = 6
	SECURITY_LOCAL_SYSTEM_RID           = 18
	SECURITY_BUILTIN_DOMAIN_RID         = 32
	SECURITY_PRINCIPAL_SELF_RID         = 10
	SECURITY_CREATOR_OWNER_SERVER_RID   = 0x2
	SECURITY_CREATOR_GROUP_SERVER_RID   = 0x3
	SECURITY_LOGON_IDS_RID_COUNT        = 0x3
	SECURITY_ANONYMOUS_LOGON_RID        = 0x7
	SECURITY_PROXY_RID                  = 0x8
	SECURITY_ENTERPRISE_CONTROLLERS_RID = 0x9
	SECURITY_SERVER_LOGON_RID           = SECURITY_ENTERPRISE_CONTROLLERS_RID
	SECURITY_AUTHENTICATED_USER_RID     = 0xb
	SECURITY_RESTRICTED_CODE_RID        = 0xc
	SECURITY_NT_NON_UNIQUE_RID          = 0x15
)

// Predefined domain-relative RIDs for local groups.
// See https://msdn.microsoft.com/en-us/library/windows/desktop/aa379649(v=vs.85).aspx
const (
	DOMAIN_ALIAS_RID_ADMINS                         = 0x220
	DOMAIN_ALIAS_RID_USERS                          = 0x221
	DOMAIN_ALIAS_RID_GUESTS                         = 0x222
	DOMAIN_ALIAS_RID_POWER_USERS                    = 0x223
	DOMAIN_ALIAS_RID_ACCOUNT_OPS                    = 0x224
	DOMAIN_ALIAS_RID_SYSTEM_OPS                     = 0x225
	DOMAIN_ALIAS_RID_PRINT_OPS                      = 0x226
	DOMAIN_ALIAS_RID_BACKUP_OPS                     = 0x227
	DOMAIN_ALIAS_RID_REPLICATOR                     = 0x228
	DOMAIN_ALIAS_RID_RAS_SERVERS                    = 0x229
	DOMAIN_ALIAS_RID_PREW2KCOMPACCESS               = 0x22a
	DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS           = 0x22b
	DOMAIN_ALIAS_RID_NETWORK_CONFIGURATION_OPS      = 0x22c
	DOMAIN_ALIAS_RID_INCOMING_FOREST_TRUST_BUILDERS = 0x22d
	DOMAIN_ALIAS_RID_MONITORING_USERS               = 0x22e
	DOMAIN_ALIAS_RID_LOGGING_USERS                  = 0x22f
	DOMAIN_ALIAS_RID_AUTHORIZATIONACCESS            = 0x230
	DOMAIN_ALIAS_RID_TS_LICENSE_SERVERS             = 0x231
	DOMAIN_ALIAS_RID_DCOM_USERS                     = 0x232
	DOMAIN_ALIAS_RID_IUSERS                         = 0x238
	DOMAIN_ALIAS_RID_CRYPTO_OPERATORS               = 0x239
	DOMAIN_ALIAS_RID_CACHEABLE_PRINCIPALS_GROUP     = 0x23b
	DOMAIN_ALIAS_RID_NON_CACHEABLE_PRINCIPALS_GROUP = 0x23c
	DOMAIN_ALIAS_RID_EVENT_LOG_READERS_GROUP        = 0x23d
	DOMAIN_ALIAS_RID_CERTSVC_DCOM_ACCESS_GROUP      = 0x23e
)

type SID struct{}

// Various types of pre-specified SIDs that can be synthesized and compared at runtime.
type WELL_KNOWN_SID_TYPE uint32

const (
	WinNullSid                                    = 0
	WinWorldSid                                   = 1
	WinLocalSid                                   = 2
	WinCreatorOwnerSid                            = 3
	WinCreatorGroupSid                            = 4
	WinCreatorOwnerServerSid                      = 5
	WinCreatorGroupServerSid                      = 6
	WinNtAuthoritySid                             = 7
	WinDialupSid                                  = 8
	WinNetworkSid                                 = 9
	WinBatchSid                                   = 10
	WinInteractiveSid                             = 11
	WinServiceSid                                 = 12
	WinAnonymousSid                               = 13
	WinProxySid                                   = 14
	WinEnterpriseControllersSid                   = 15
	WinSelfSid                                    = 16
	WinAuthenticatedUserSid                       = 17
	WinRestrictedCodeSid                          = 18
	WinTerminalServerSid                          = 19
	WinRemoteLogonIdSid                           = 20
	WinLogonIdsSid                                = 21
	WinLocalSystemSid                             = 22
	WinLocalServiceSid                            = 23
	WinNetworkServiceSid                          = 24
	WinBuiltinDomainSid                           = 25
	WinBuiltinAdministratorsSid                   = 26
	WinBuiltinUsersSid                            = 27
	WinBuiltinGuestsSid                           = 28
	WinBuiltinPowerUsersSid                       = 29
	WinBuiltinAccountOperatorsSid                 = 30
	WinBuiltinSystemOperatorsSid                  = 31
	WinBuiltinPrintOperatorsSid                   = 32
	WinBuiltinBackupOperatorsSid                  = 33
	WinBuiltinReplicatorSid                       = 34
	WinBuiltinPreWindows2000CompatibleAccessSid   = 35
	WinBuiltinRemoteDesktopUsersSid               = 36
	WinBuiltinNetworkConfigurationOperatorsSid    = 37
	WinAccountAdministratorSid                    = 38
	WinAccountGuestSid                            = 39
	WinAccountKrbtgtSid                           = 40
	WinAccountDomainAdminsSid                     = 41
	WinAccountDomainUsersSid                      = 42
	WinAccountDomainGuestsSid                     = 43
	WinAccountComputersSid                        = 44
	WinAccountControllersSid                      = 45
	WinAccountCertAdminsSid                       = 46
	WinAccountSchemaAdminsSid                     = 47
	WinAccountEnterpriseAdminsSid                 = 48
	WinAccountPolicyAdminsSid                     = 49
	WinAccountRasAndIasServersSid                 = 50
	WinNTLMAuthenticationSid                      = 51
	WinDigestAuthenticationSid                    = 52
	WinSChannelAuthenticationSid                  = 53
	WinThisOrganizationSid                        = 54
	WinOtherOrganizationSid                       = 55
	WinBuiltinIncomingForestTrustBuildersSid      = 56
	WinBuiltinPerfMonitoringUsersSid              = 57
	WinBuiltinPerfLoggingUsersSid                 = 58
	WinBuiltinAuthorizationAccessSid              = 59
	WinBuiltinTerminalServerLicenseServersSid     = 60
	WinBuiltinDCOMUsersSid                        = 61
	WinBuiltinIUsersSid                           = 62
	WinIUserSid                                   = 63
	WinBuiltinCryptoOperatorsSid                  = 64
	WinUntrustedLabelSid                          = 65
	WinLowLabelSid                                = 66
	WinMediumLabelSid                             = 67
	WinHighLabelSid                               = 68
	WinSystemLabelSid                             = 69
	WinWriteRestrictedCodeSid                     = 70
	WinCreatorOwnerRightsSid                      = 71
	WinCacheablePrincipalsGroupSid                = 72
	WinNonCacheablePrincipalsGroupSid             = 73
	WinEnterpriseReadonlyControllersSid           = 74
	WinAccountReadonlyControllersSid              = 75
	WinBuiltinEventLogReadersGroup                = 76
	WinNewEnterpriseReadonlyControllersSid        = 77
	WinBuiltinCertSvcDComAccessGroup              = 78
	WinMediumPlusLabelSid                         = 79
	WinLocalLogonSid                              = 80
	WinConsoleLogonSid                            = 81
	WinThisOrganizationCertificateSid             = 82
	WinApplicationPackageAuthoritySid             = 83
	WinBuiltinAnyPackageSid                       = 84
	WinCapabilityInternetClientSid                = 85
	WinCapabilityInternetClientServerSid          = 86
	WinCapabilityPrivateNetworkClientServerSid    = 87
	WinCapabilityPicturesLibrarySid               = 88
	WinCapabilityVideosLibrarySid                 = 89
	WinCapabilityMusicLibrarySid                  = 90
	WinCapabilityDocumentsLibrarySid              = 91
	WinCapabilitySharedUserCertificatesSid        = 92
	WinCapabilityEnterpriseAuthenticationSid      = 93
	WinCapabilityRemovableStorageSid              = 94
	WinBuiltinRDSRemoteAccessServersSid           = 95
	WinBuiltinRDSEndpointServersSid               = 96
	WinBuiltinRDSManagementServersSid             = 97
	WinUserModeDriversSid                         = 98
	WinBuiltinHyperVAdminsSid                     = 99
	WinAccountCloneableControllersSid             = 100
	WinBuiltinAccessControlAssistanceOperatorsSid = 101
	WinBuiltinRemoteManagementUsersSid            = 102
	WinAuthenticationAuthorityAssertedSid         = 103
	WinAuthenticationServiceAssertedSid           = 104
	WinLocalAccountSid                            = 105
	WinLocalAccountAndAdministratorSid            = 106
	WinAccountProtectedUsersSid                   = 107
	WinCapabilityAppointmentsSid                  = 108
	WinCapabilityContactsSid                      = 109
	WinAccountDefaultSystemManagedSid             = 110
	WinBuiltinDefaultSystemManagedGroupSid        = 111
	WinBuiltinStorageReplicaAdminsSid             = 112
	WinAccountKeyAdminsSid                        = 113
	WinAccountEnterpriseKeyAdminsSid              = 114
	WinAuthenticationKeyTrustSid                  = 115
	WinAuthenticationKeyPropertyMFASid            = 116
	WinAuthenticationKeyPropertyAttestationSid    = 117
	WinAuthenticationFreshKeyAuthSid              = 118
	WinBuiltinDeviceOwnersSid                     = 119
)

const (
	// do not reorder
	TOKEN_ASSIGN_PRIMARY = 1 << iota
	TOKEN_DUPLICATE
	TOKEN_IMPERSONATE
	TOKEN_QUERY
	TOKEN_QUERY_SOURCE
	TOKEN_ADJUST_PRIVILEGES
	TOKEN_ADJUST_GROUPS
	TOKEN_ADJUST_DEFAULT
	TOKEN_ADJUST_SESSIONID

	TOKEN_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
		TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE |
		TOKEN_IMPERSONATE |
		TOKEN_QUERY |
		TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES |
		TOKEN_ADJUST_GROUPS |
		TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID
	TOKEN_READ  = STANDARD_RIGHTS_READ | TOKEN_QUERY
	TOKEN_WRITE = STANDARD_RIGHTS_WRITE |
		TOKEN_ADJUST_PRIVILEGES |
		TOKEN_ADJUST_GROUPS |
		TOKEN_ADJUST_DEFAULT
	TOKEN_EXECUTE = STANDARD_RIGHTS_EXECUTE
)

const (
	// do not reorder
	TokenUser = 1 + iota
	TokenGroups
	TokenPrivileges
	TokenOwner
	TokenPrimaryGroup
	TokenDefaultDacl
	TokenSource
	TokenType
	TokenImpersonationLevel
	TokenStatistics
	TokenRestrictedSids
	TokenSessionId
	TokenGroupsAndPrivileges
	TokenSessionReference
	TokenSandBoxInert
	TokenAuditPolicy
	TokenOrigin
	TokenElevationType
	TokenLinkedToken
	TokenElevation
	TokenHasRestrictions
	TokenAccessInformation
	TokenVirtualizationAllowed
	TokenVirtualizationEnabled
	TokenIntegrityLevel
	TokenUIAccess
	TokenMandatoryPolicy
	TokenLogonSid
	MaxTokenInfoClass
)

// Group attributes inside of Tokengroups.Groups[i].Attributes
const (
	SE_GROUP_MANDATORY          = 0x00000001
	SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002
	SE_GROUP_ENABLED            = 0x00000004
	SE_GROUP_OWNER              = 0x00000008
	SE_GROUP_USE_FOR_DENY_ONLY  = 0x00000010
	SE_GROUP_INTEGRITY          = 0x00000020
	SE_GROUP_INTEGRITY_ENABLED  = 0x00000040
	SE_GROUP_LOGON_ID           = 0xC0000000
	SE_GROUP_RESOURCE           = 0x20000000
	SE_GROUP_VALID_ATTRIBUTES   = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED | SE_GROUP_OWNER | SE_GROUP_USE_FOR_DENY_ONLY | SE_GROUP_LOGON_ID | SE_GROUP_RESOURCE | SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED
)

// Privilege attributes
const (
	SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
	SE_PRIVILEGE_ENABLED            = 0x00000002
	SE_PRIVILEGE_REMOVED            = 0x00000004
	SE_PRIVILEGE_USED_FOR_ACCESS    = 0x80000000
	SE_PRIVILEGE_VALID_ATTRIBUTES   = SE_PRIVILEGE_ENABLED_BY_DEFAULT | SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_REMOVED | SE_PRIVILEGE_USED_FOR_ACCESS
)

// Token types
const (
	TokenPrimary       = 1
	TokenImpersonation = 2
)

// Impersonation levels
const (
	SecurityAnonymous      = 0
	SecurityIdentification = 1
	SecurityImpersonation  = 2
	SecurityDelegation     = 3
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUIDAndAttributes struct {
	Luid       LUID
	Attributes uint32
}

type SIDAndAttributes struct {
	Sid        *SID
	Attributes uint32
}

type Tokenuser struct {
	User SIDAndAttributes
}

type Tokenprimarygroup struct {
	PrimaryGroup *SID
}

type Tokengroups struct {
	GroupCount uint32
	Groups     [1]SIDAndAttributes // Use AllGroups() for iterating.
}

const (
	WTS_CONSOLE_CONNECT        = 0x1
	WTS_CONSOLE_DISCONNECT     = 0x2
	WTS_REMOTE_CONNECT         = 0x3
	WTS_REMOTE_DISCONNECT      = 0x4
	WTS_SESSION_LOGON          = 0x5
	WTS_SESSION_LOGOFF         = 0x6
	WTS_SESSION_LOCK           = 0x7
	WTS_SESSION_UNLOCK         = 0x8
	WTS_SESSION_REMOTE_CONTROL = 0x9
	WTS_SESSION_CREATE         = 0xa
	WTS_SESSION_TERMINATE      = 0xb
)

const (
	WTSActive       = 0
	WTSConnected    = 1
	WTSConnectQuery = 2
	WTSShadow       = 3
	WTSDisconnected = 4
	WTSIdle         = 5
	WTSListen       = 6
	WTSReset        = 7
	WTSDown         = 8
	WTSInit         = 9
)

type WTSSESSION_NOTIFICATION struct {
	Size      uint32
	SessionID uint32
}

type WTS_SESSION_INFO struct {
	SessionID         uint32
	WindowStationName *uint16
	State             uint32
}

//sys WTSQueryUserToken(session uint32, token *Token) (err error) = wtsapi32.WTSQueryUserToken
//sys WTSEnumerateSessions(handle Handle, reserved uint32, version uint32, sessions **WTS_SESSION_INFO, count *uint32) (err error) = wtsapi32.WTSEnumerateSessionsW
//sys WTSFreeMemory(ptr uintptr) = wtsapi32.WTSFreeMemory
//sys WTSGetActiveConsoleSessionId() (sessionID uint32)

type ACL struct {
	aclRevision byte
	sbz1        byte
	aclSize     uint16
	aceCount    uint16
	sbz2        uint16
}

type SECURITY_DESCRIPTOR struct {
	revision byte
	sbz1     byte
	control  SECURITY_DESCRIPTOR_CONTROL
	owner    *SID
	group    *SID
	sacl     *ACL
	dacl     *ACL
}

type SECURITY_QUALITY_OF_SERVICE struct {
	Length              uint32
	ImpersonationLevel  uint32
	ContextTrackingMode byte
	EffectiveOnly       byte
}

// Constants for the ContextTrackingMode field of SECURITY_QUALITY_OF_SERVICE.
const (
	SECURITY_STATIC_TRACKING  = 0
	SECURITY_DYNAMIC_TRACKING = 1
)

type SecurityAttributes struct {
	Length             uint32
	SecurityDescriptor *SECURITY_DESCRIPTOR
	InheritHandle      uint32
}

type SE_OBJECT_TYPE uint32

// Constants for type SE_OBJECT_TYPE
const (
	SE_UNKNOWN_OBJECT_TYPE     = 0
	SE_FILE_OBJECT             = 1
	SE_SERVICE                 = 2
	SE_PRINTER                 = 3
	SE_REGISTRY_KEY            = 4
	SE_LMSHARE                 = 5
	SE_KERNEL_OBJECT           = 6
	SE_WINDOW_OBJECT           = 7
	SE_DS_OBJECT               = 8
	SE_DS_OBJECT_ALL           = 9
	SE_PROVIDER_DEFINED_OBJECT = 10
	SE_WMIGUID_OBJECT          = 11
	SE_REGISTRY_WOW64_32KEY    = 12
	SE_REGISTRY_WOW64_64KEY    = 13
)

type SECURITY_INFORMATION uint32

// Constants for type SECURITY_INFORMATION
const (
	OWNER_SECURITY_INFORMATION            = 0x00000001
	GROUP_SECURITY_INFORMATION            = 0x00000002
	DACL_SECURITY_INFORMATION             = 0x00000004
	SACL_SECURITY_INFORMATION             = 0x00000008
	LABEL_SECURITY_INFORMATION            = 0x00000010
	ATTRIBUTE_SECURITY_INFORMATION        = 0x00000020
	SCOPE_SECURITY_INFORMATION            = 0x00000040
	BACKUP_SECURITY_INFORMATION           = 0x00010000
	PROTECTED_DACL_SECURITY_INFORMATION   = 0x80000000
	PROTECTED_SACL_SECURITY_INFORMATION   = 0x40000000
	UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
	UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
)

type SECURITY_DESCRIPTOR_CONTROL uint16

// Constants for type SECURITY_DESCRIPTOR_CONTROL
const (
	SE_OWNER_DEFAULTED       = 0x0001
	SE_GROUP_DEFAULTED       = 0x0002
	SE_DACL_PRESENT          = 0x0004
	SE_DACL_DEFAULTED        = 0x0008
	SE_SACL_PRESENT          = 0x0010
	SE_SACL_DEFAULTED        = 0x0020
	SE_DACL_AUTO_INHERIT_REQ = 0x0100
	SE_SACL_AUTO_INHERIT_REQ = 0x0200
	SE_DACL_AUTO_INHERITED   = 0x0400
	SE_SACL_AUTO_INHERITED   = 0x0800
	SE_DACL_PROTECTED        = 0x1000
	SE_SACL_PROTECTED        = 0x2000
	SE_RM_CONTROL_VALID      = 0x4000
	SE_SELF_RELATIVE         = 0x8000
)

type ACCESS_MASK uint32

// Constants for type ACCESS_MASK
const (
	DELETE                   = 0x00010000
	READ_CONTROL             = 0x00020000
	WRITE_DAC                = 0x00040000
	WRITE_OWNER              = 0x00080000
	SYNCHRONIZE              = 0x00100000
	STANDARD_RIGHTS_REQUIRED = 0x000F0000
	STANDARD_RIGHTS_READ     = READ_CONTROL
	STANDARD_RIGHTS_WRITE    = READ_CONTROL
	STANDARD_RIGHTS_EXECUTE  = READ_CONTROL
	STANDARD_RIGHTS_ALL      = 0x001F0000
	SPECIFIC_RIGHTS_ALL      = 0x0000FFFF
	ACCESS_SYSTEM_SECURITY   = 0x01000000
	MAXIMUM_ALLOWED          = 0x02000000
	GENERIC_READ             = 0x80000000
	GENERIC_WRITE            = 0x40000000
	GENERIC_EXECUTE          = 0x20000000
	GENERIC_ALL              = 0x10000000
	SEC_COMMIT               = 0x8000000
	SECTION_WRITE            = 0x2
	SECTION_READ             = 0x4
	SECTION_EXECUTE          = 0x8
	SECTION_ALL              = 0x1 | SECTION_READ | SECTION_WRITE | SECTION_EXECUTE | 0x10 | 0xf0000
)

type ACCESS_MODE uint32

// Constants for type ACCESS_MODE
const (
	NOT_USED_ACCESS   = 0
	GRANT_ACCESS      = 1
	SET_ACCESS        = 2
	DENY_ACCESS       = 3
	REVOKE_ACCESS     = 4
	SET_AUDIT_SUCCESS = 5
	SET_AUDIT_FAILURE = 6
)

// Constants for AceFlags and Inheritance fields
const (
	NO_INHERITANCE                     = 0x0
	SUB_OBJECTS_ONLY_INHERIT           = 0x1
	SUB_CONTAINERS_ONLY_INHERIT        = 0x2
	SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3
	INHERIT_NO_PROPAGATE               = 0x4
	INHERIT_ONLY                       = 0x8
	INHERITED_ACCESS_ENTRY             = 0x10
	INHERITED_PARENT                   = 0x10000000
	INHERITED_GRANDPARENT              = 0x20000000
	OBJECT_INHERIT_ACE                 = 0x1
	CONTAINER_INHERIT_ACE              = 0x2
	NO_PROPAGATE_INHERIT_ACE           = 0x4
	INHERIT_ONLY_ACE                   = 0x8
	INHERITED_ACE                      = 0x10
	VALID_INHERIT_FLAGS                = 0x1F
)

type MULTIPLE_TRUSTEE_OPERATION uint32

// Constants for MULTIPLE_TRUSTEE_OPERATION
const (
	NO_MULTIPLE_TRUSTEE    = 0
	TRUSTEE_IS_IMPERSONATE = 1
)

type TRUSTEE_FORM uint32

// Constants for TRUSTEE_FORM
const (
	TRUSTEE_IS_SID              = 0
	TRUSTEE_IS_NAME             = 1
	TRUSTEE_BAD_FORM            = 2
	TRUSTEE_IS_OBJECTS_AND_SID  = 3
	TRUSTEE_IS_OBJECTS_AND_NAME = 4
)

type TRUSTEE_TYPE uint32

// Constants for TRUSTEE_TYPE
const (
	TRUSTEE_IS_UNKNOWN          = 0
	TRUSTEE_IS_USER             = 1
	TRUSTEE_IS_GROUP            = 2
	TRUSTEE_IS_DOMAIN           = 3
	TRUSTEE_IS_ALIAS            = 4
	TRUSTEE_IS_WELL_KNOWN_GROUP = 5
	TRUSTEE_IS_DELETED          = 6
	TRUSTEE_IS_INVALID          = 7
	TRUSTEE_IS_COMPUTER         = 8
)

// Constants for ObjectsPresent field
const (
	ACE_OBJECT_TYPE_PRESENT           = 0x1
	ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2
)

type EXPLICIT_ACCESS struct {
	AccessPermissions ACCESS_MASK
	AccessMode        ACCESS_MODE
	Inheritance       uint32
	Trustee           TRUSTEE
}

// This type is the union inside of TRUSTEE and must be created using one of the TrusteeValueFrom* functions.
type TrusteeValue uintptr

func TrusteeValueFromString(str string) TrusteeValue {
	return TrusteeValue(unsafe.Pointer(StringToUTF16Ptr(str)))
}
func TrusteeValueFromSID(sid *SID) TrusteeValue {
	return TrusteeValue(unsafe.Pointer(sid))
}
func TrusteeValueFromObjectsAndSid(objectsAndSid *OBJECTS_AND_SID) TrusteeValue {
	return TrusteeValue(unsafe.Pointer(objectsAndSid))
}
func TrusteeValueFromObjectsAndName(objectsAndName *OBJECTS_AND_NAME) TrusteeValue {
	return TrusteeValue(unsafe.Pointer(objectsAndName))
}

type TRUSTEE struct {
	MultipleTrustee          *TRUSTEE
	MultipleTrusteeOperation MULTIPLE_TRUSTEE_OPERATION
	TrusteeForm              TRUSTEE_FORM
	TrusteeType              TRUSTEE_TYPE
	TrusteeValue             TrusteeValue
}

type OBJECTS_AND_SID struct {
	ObjectsPresent          uint32
	ObjectTypeGuid          GUID
	InheritedObjectTypeGuid GUID
	Sid                     *SID
}

type OBJECTS_AND_NAME struct {
	ObjectsPresent          uint32
	ObjectType              SE_OBJECT_TYPE
	ObjectTypeName          *uint16
	InheritedObjectTypeName *uint16
	Name                    *uint16
}

type Token Handle
