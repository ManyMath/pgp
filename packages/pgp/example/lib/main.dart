import 'package:flutter/material.dart';
import 'package:pgp/pgp.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await PgpFlutter.ensureInitialized();
  runApp(const PgpExampleApp());
}

/// Result of one encrypt/decrypt and sign/verify round trip.
class RoundTrip {
  const RoundTrip({
    required this.fingerprint,
    required this.ciphertext,
    required this.plaintext,
    required this.verified,
  });

  final String fingerprint;
  final String ciphertext;
  final String plaintext;
  final String verified;
}

/// Generates a certificate and round-trips [message] through it.
RoundTrip roundTrip(String message) {
  final pgp = PGP();
  final cert = pgp.generateKey('example@example.org');
  final publicCert = pgp.certificateFromArmored(cert.exportPublicArmored());
  try {
    final ciphertext = publicCert.encrypt(message);
    return RoundTrip(
      fingerprint: cert.fingerprint(),
      ciphertext: ciphertext,
      plaintext: cert.decrypt(ciphertext),
      verified: publicCert.verify(cert.sign(message)),
    );
  } finally {
    publicCert.dispose();
    cert.dispose();
  }
}

class PgpExampleApp extends StatefulWidget {
  const PgpExampleApp({super.key});

  @override
  State<PgpExampleApp> createState() => _PgpExampleAppState();
}

class _PgpExampleAppState extends State<PgpExampleApp> {
  final _message = TextEditingController(text: 'hello');
  RoundTrip? _result;
  String? _error;

  @override
  void dispose() {
    _message.dispose();
    super.dispose();
  }

  void _run() {
    setState(() {
      try {
        _result = roundTrip(_message.text);
        _error = null;
      } on Object catch (e) {
        _result = null;
        _error = '$e';
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    final result = _result;
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('pgp')),
        body: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            TextField(
              key: const Key('message'),
              controller: _message,
              decoration: const InputDecoration(labelText: 'Message'),
            ),
            const SizedBox(height: 12),
            FilledButton(
              key: const Key('run'),
              onPressed: _run,
              child: const Text('Generate key and round-trip'),
            ),
            const SizedBox(height: 16),
            if (_error != null) Text(_error!, key: const Key('error')),
            if (result != null) ...[
              Text('Fingerprint: ${result.fingerprint}'),
              const SizedBox(height: 8),
              Text(
                'Decrypted: ${result.plaintext}',
                key: const Key('decrypted'),
              ),
              Text('Verified: ${result.verified}', key: const Key('verified')),
              const SizedBox(height: 8),
              SelectableText(
                result.ciphertext,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
