import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:pgp_flutter/pgp_flutter.dart';
import 'package:pgp_flutter_example/main.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  test('the bundled library loads', () async {
    expect(await PgpFlutter.ensureInitialized(), 'ffi');
  });

  test('encrypt/decrypt and sign/verify round-trip', () {
    final result = roundTrip('integration');
    expect(result.plaintext, 'integration');
    expect(result.verified, 'integration');
    expect(result.ciphertext, startsWith('-----BEGIN PGP MESSAGE-----'));
  });

  testWidgets('the app round-trips its message', (tester) async {
    await tester.pumpWidget(const PgpExampleApp());
    await tester.tap(find.byKey(const Key('run')));
    await tester.pumpAndSettle();
    expect(find.text('Decrypted: hello'), findsOneWidget);
    expect(find.text('Verified: hello'), findsOneWidget);
  });
}
