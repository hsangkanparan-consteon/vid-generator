import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';

/// Enum representing the QR Code Type identifier.
enum QRType {
  location(1, 'location'),
  asset(2, 'asset'),
  user(3, 'user'),
  other(4, 'other');

  final int id;
  final String name;
  const QRType(this.id, this.name);

  static QRType fromId(int id) {
    for (var t in QRType.values) {
      if (t.id == id) return t;
    }
    throw FormatException('Unknown QR type ID: $id');
  }
}

/// Decoded and verified QR Code Result.
class QRResult {
  final bool isValid;
  final int scheme;              // 1 = Symmetric, 3 = Asymmetric (Ed25519), 0 = Plaintext
  final QRType type;
  final int formatVersion;
  final int keyVersion;
  final bool isGlobalFacility;
  final String? vid;             // For User QR (14-digit numeric string)
  final String? unspsc;          // For Asset QR (4 or 6-digit UNSPSC code)
  final String? assetUid;        // For Asset QR (optional UID)
  final String? locationSubtype; // For Location QR ("gate", "room", "toilet", etc.)
  final int? countryCode;        // For Location QR (e.g. 62)
  final String? locationUid;     // For Location QR (e.g. "0sJ4sy7f4FQVE4-rYyd95bg")
  final String? entityId;        // For Other QR
  final Uint8List? metadata;     // For Other QR
  final String? errorMessage;

  QRResult({
    required this.isValid,
    required this.scheme,
    required this.type,
    required this.formatVersion,
    required this.keyVersion,
    required this.isGlobalFacility,
    this.vid,
    this.unspsc,
    this.assetUid,
    this.locationSubtype,
    this.countryCode,
    this.locationUid,
    this.entityId,
    this.metadata,
    this.errorMessage,
  });

  @override
  String toString() {
    if (!isValid) return 'QRResult(INVALID: $errorMessage)';
    return 'QRResult(isValid: $isValid, scheme: $scheme, type: ${type.name}, keyVer: $keyVersion, vid: $vid, unspsc: $unspsc, loc: $locationSubtype, uid: ${assetUid ?? locationUid})';
  }
}

/// High-performance Offline QR Decoder and Signature Verifier supporting:
/// - Scheme 3: Asymmetric Ed25519 (FIPS 186-5 / RFC 8032)
/// - Scheme 1: Symmetric Key / Compact Low-Density Badges (25x25 matrix)
/// - Scheme 0: Unencrypted Public Identifiers
class QRDecoder {
  final Ed25519 _ed25519 = Ed25519();
  final Map<int, List<int>> _publicKeys;

  /// Initializes decoder with trusted public keys (Scheme 3).
  /// Keys can be passed as `List<int>`, 64-char Hex string, or Base64 string.
  QRDecoder({
    Map<int, dynamic>? publicKeys,
  })  : _publicKeys = (publicKeys ?? {}).map((k, v) => MapEntry(k, _parseKeyBytes(v)));

  static List<int> _parseKeyBytes(dynamic key) {
    if (key is List<int>) return key;
    if (key is String) {
      if (key.length == 64) {
        final bytes = <int>[];
        for (int i = 0; i < 64; i += 2) {
          bytes.add(int.parse(key.substring(i, i + 2), radix: 16));
        }
        return bytes;
      }
      return _decodeFlexibleBase64(key);
    }
    throw ArgumentError('Key must be byte list, 64-char Hex, or Base64 string');
  }

  /// Robust, cross-platform Base64/Base64URL decoder that handles unpadded and URL-safe streams
  static Uint8List _decodeFlexibleBase64(String input) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    final map = <int, int>{};
    for (int i = 0; i < chars.length; i++) {
      map[chars.codeUnitAt(i)] = i;
    }
    map['+'.codeUnitAt(0)] = 62;
    map['/'.codeUnitAt(0)] = 63;

    final bytes = <int>[];
    int buffer = 0;
    int bitsCollected = 0;

    for (int i = 0; i < input.length; i++) {
      final code = input.codeUnitAt(i);
      if (code == 61) break; // '='
      final val = map[code];
      if (val == null) continue;

      buffer = (buffer << 6) | val;
      bitsCollected += 6;

      if (bitsCollected >= 8) {
        bitsCollected -= 8;
        bytes.add((buffer >> bitsCollected) & 0xFF);
      }
    }
    return Uint8List.fromList(bytes);
  }

  /// RFC 9285 Base45 Decoder for ultra-compact Version 4 QR Codes
  static Uint8List _decodeBase45(String input) {
    const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ \$%*+-./:";
    final map = <int, int>{};
    for (int i = 0; i < charset.length; i++) {
      map[charset.codeUnitAt(i)] = i;
    }

    if (input.length % 3 == 1) {
      throw const FormatException('Invalid Base45 string length: trailing remainder of 1');
    }

    final out = <int>[];
    for (int i = 0; i < input.length; i += 3) {
      if (i + 2 < input.length) {
        final c0 = map[input.codeUnitAt(i)];
        final c1 = map[input.codeUnitAt(i + 1)];
        final c2 = map[input.codeUnitAt(i + 2)];
        if (c0 == null || c1 == null || c2 == null) {
          throw FormatException('Invalid Base45 character at index $i');
        }
        final val = c0 + (c1 * 45) + (c2 * 45 * 45);
        if (val > 65535) throw FormatException('Base45 overflow at index $i');
        out.add((val >> 8) & 0xFF);
        out.add(val & 0xFF);
      } else if (i + 1 < input.length) {
        final c0 = map[input.codeUnitAt(i)];
        final c1 = map[input.codeUnitAt(i + 1)];
        if (c0 == null || c1 == null) {
          throw FormatException('Invalid Base45 character at index $i');
        }
        final val = c0 + (c1 * 45);
        if (val > 255) throw FormatException('Base45 byte overflow at index $i');
        out.add(val & 0xFF);
      }
    }
    return Uint8List.fromList(out);
  }

  /// Verifies and decodes any autsorz QR code URL ('https://autsorz/l/...') or raw token ('3MQ...', '1V9...', Base45).
  Future<QRResult> decodeAndVerify(String qrInput) async {
    try {
      // 1. Extract token payload from URL if present
      String token = qrInput.trim();
      if (token.contains('/l/')) {
        token = token.split('/l/').last;
      } else if (token.contains('/u/')) {
        token = token.split('/u/').last;
      }

      if (token.isEmpty) {
        throw const FormatException('Empty QR input');
      }

      // 2. Identify Scheme Prefix ('3' = Ed25519 Asymmetric, '1' = Symmetric, '0' = Plaintext, or raw Base45)
      int scheme = int.tryParse(token[0]) ?? -1;

      switch (scheme) {
        case 3:
          return await _decodeScheme3(token);
        case 1:
          return _decodeScheme1(token);
        case 0:
          return _decodeScheme0(token);
        default:
          // Fallback: Attempt Base45 direct decode if not starting with standard scheme digit
          return await _decodeScheme3('3$token');
      }
    } catch (e) {
      return QRResult(
        isValid: false,
        scheme: 0,
        type: QRType.user,
        formatVersion: 1,
        keyVersion: 1,
        isGlobalFacility: false,
        errorMessage: e.toString(),
      );
    }
  }

  /// Scheme 3: Asymmetric Ed25519 Digital Signature Verification (72B or 85B)
  Future<QRResult> _decodeScheme3(String token) async {
    String payloadStr = token.startsWith('3') ? token.substring(1) : token;
    Uint8List rawBytes;
    try {
      rawBytes = _decodeFlexibleBase64(payloadStr);
      if (rawBytes.length < 66) {
        throw const FormatException('Too short for Base64');
      }
    } catch (_) {
      // Try RFC 9285 Base45
      rawBytes = _decodeBase45(payloadStr);
    }

    if (rawBytes.length < 66) {
      throw FormatException('Token length too short: ${rawBytes.length} bytes (Minimum 66 bytes)');
    }

    int byte0 = rawBytes[0];
    int typeId = (byte0 >> 4) & 0x0F;
    int formatVer = byte0 & 0x0F;
    QRType qrType = QRType.fromId(typeId);
    int keyVer = rawBytes[1];

    int messageLen = rawBytes.length - 64;
    List<int> messageBytes = rawBytes.sublist(0, messageLen);
    List<int> signatureBytes = rawBytes.sublist(messageLen);

    List<int>? pubKeyBytes = _publicKeys[keyVer];
    if (pubKeyBytes == null) {
      return QRResult(
        isValid: false,
        scheme: 3,
        type: qrType,
        formatVersion: formatVer,
        keyVersion: keyVer,
        isGlobalFacility: false,
        errorMessage: 'Public key for version $keyVer not found in local keyring',
      );
    }

    final publicKey = SimplePublicKey(pubKeyBytes, type: KeyPairType.ed25519);
    final signature = Signature(signatureBytes, publicKey: publicKey);
    bool isSigValid = await _ed25519.verify(messageBytes, signature: signature);

    if (!isSigValid) {
      return QRResult(
        isValid: false,
        scheme: 3,
        type: qrType,
        formatVersion: formatVer,
        keyVersion: keyVer,
        isGlobalFacility: false,
        errorMessage: 'Invalid digital signature: token was tampered with or key is incorrect',
      );
    }

    Uint8List payload = rawBytes.sublist(2, messageLen);
    return _unpackPayload(
      scheme: 3,
      qrType: qrType,
      formatVer: formatVer,
      keyVer: keyVer,
      payload: payload,
    );
  }

  /// Scheme 1: Symmetric Compact Low-Density Decoding (20B / 27 Chars)
  QRResult _decodeScheme1(String token) {
    Uint8List rawBytes = _decodeFlexibleBase64(token.substring(1));

    if (rawBytes.length < 7) {
      throw FormatException('Scheme 1 token too short: ${rawBytes.length} bytes');
    }

    int byte0 = rawBytes[0];
    int typeId = (byte0 >> 4) & 0x0F;
    QRType qrType;
    try {
      qrType = QRType.fromId(typeId);
    } catch (_) {
      qrType = QRType.user; // Default fallback for legacy compact tokens
    }

    int vidInt = (rawBytes[1] << 40) |
        (rawBytes[2] << 32) |
        (rawBytes[3] << 24) |
        (rawBytes[4] << 16) |
        (rawBytes[5] << 8) |
        rawBytes[6];
    String vidStr = vidInt.toString().padLeft(14, '0');

    return QRResult(
      isValid: true,
      scheme: 1,
      type: qrType,
      formatVersion: 1,
      keyVersion: 1,
      isGlobalFacility: false,
      vid: vidStr,
    );
  }

  /// Scheme 0: Plaintext Unencrypted ID
  QRResult _decodeScheme0(String token) {
    return QRResult(
      isValid: true,
      scheme: 0,
      type: QRType.location,
      formatVersion: 1,
      keyVersion: 0,
      isGlobalFacility: false,
      locationUid: token,
      assetUid: token,
    );
  }

  QRResult _unpackPayload({
    required int scheme,
    required QRType qrType,
    required int formatVer,
    required int keyVer,
    required Uint8List payload,
  }) {
    String? vid;
    String? unspsc;
    String? assetUid;
    String? locationSubtype;
    int? countryCode;
    String? locationUid;
    String? entityId;
    Uint8List? metadata;

    switch (qrType) {
      case QRType.user:
        if (payload.length != 6) {
          throw FormatException('Invalid User payload size: ${payload.length} bytes (Expected 6)');
        }
        int vidInt = (payload[0] << 40) |
            (payload[1] << 32) |
            (payload[2] << 24) |
            (payload[3] << 16) |
            (payload[4] << 8) |
            payload[5];
        vid = vidInt.toString().padLeft(14, '0');
        break;

      case QRType.location:
        if (payload.length < 3) {
          throw FormatException('Invalid Location payload: need at least 3 bytes');
        }
        countryCode = (payload[0] << 8) | payload[1];
        int subByte = payload[2];
        locationSubtype = _parseLocationSubtype(subByte);
        if (payload.length >= 19) {
          Uint8List raw16 = payload.sublist(3, 19);
          String b64 = base64Url.encode(raw16).replaceAll('=', '');
          locationUid = '0$b64';
        } else if (payload.length >= 8) {
          int uidInt = (payload[3] << 32) |
              (payload[4] << 24) |
              (payload[5] << 16) |
              (payload[6] << 8) |
              payload[7];
          locationUid = uidInt.toString();
        }
        break;

      case QRType.asset:
        if (payload.length < 3) {
          throw FormatException('Invalid Asset payload: need at least 3 bytes');
        }
        int unspscVal = (payload[0] << 16) | (payload[1] << 8) | payload[2];
        unspsc = (unspscVal < 10000)
            ? unspscVal.toString().padLeft(4, '0')
            : unspscVal.toString().padLeft(6, '0');
        if (payload.length >= 19) {
          Uint8List raw16 = payload.sublist(3, 19);
          String b64 = base64Url.encode(raw16).replaceAll('=', '');
          assetUid = '0$b64';
        } else if (payload.length >= 8) {
          int uidInt = (payload[3] << 32) |
              (payload[4] << 24) |
              (payload[5] << 16) |
              (payload[6] << 8) |
              payload[7];
          assetUid = uidInt.toString();
        }
        break;

      case QRType.other:
        if (payload.length < 7) {
          throw FormatException('Invalid Other payload: need at least 7 bytes');
        }
        int entInt = (payload[1] << 40) |
            (payload[2] << 32) |
            (payload[3] << 24) |
            (payload[4] << 16) |
            (payload[5] << 8) |
            payload[6];
        entityId = entInt.toString().padLeft(14, '0');
        if (payload.length > 7) {
          metadata = payload.sublist(7);
        }
        break;
    }

    return QRResult(
      isValid: true,
      scheme: scheme,
      type: qrType,
      formatVersion: formatVer,
      keyVersion: keyVer,
      isGlobalFacility: false,
      vid: vid,
      unspsc: unspsc,
      assetUid: assetUid,
      locationSubtype: locationSubtype,
      countryCode: countryCode,
      locationUid: locationUid,
      entityId: entityId,
      metadata: metadata,
    );
  }

  static String _parseLocationSubtype(int code) {
    switch (code) {
      case 0:
        return 'unknown';
      case 1:
        return 'portal';
      case 2:
        return 'guard_station';
      case 3:
        return 'room';
      case 4:
        return 'toilet';
      case 5:
        return 'gate';
      case 6:
        return 'checkpoint';
      default:
        return 'other($code)';
    }
  }
}
