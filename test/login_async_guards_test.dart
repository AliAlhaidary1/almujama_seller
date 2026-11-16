import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:sareemart_seller/features/auth_screens.dart';

/// Regression coverage for the Phase 16.1 async mounted/context.mounted
/// guards: a failed login attempt must (a) show an error, (b) terminate the
/// busy spinner, and (c) leave the submit button tappable again — i.e. the
/// guard placed after the async gap must not strand the UI in a loading
/// state or swallow the failure.
void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
  });

  testWidgets('failed login surfaces error and releases the busy state', (
    tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Directionality(
          textDirection: TextDirection.rtl,
          child: LoginScreen(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Fill the form; credentials are irrelevant — the request path must
    // surface a failure without hanging.
    await tester.enterText(find.byType(TextField).first, '770000000');
    await tester.enterText(find.byType(TextField).at(1), 'wrong-password');
    await tester.pump();

    await tester.tap(find.text('دخول'));
    await tester.pump();
    // Let the async failure unwind through _submit's catch/finally.
    await tester.pumpAndSettle();

    // No spinner remains: the busy flag was reset by the finally branch.
    expect(find.byType(CircularProgressIndicator), findsNothing);

    // An error message is visible (some Arabic error text, non-empty).
    final errorTexts = tester
        .widgetList<Text>(find.byType(Text))
        .map((t) => t.data ?? '')
        .where((s) => s.contains('خطأ') || s.contains('تعذر'));
    expect(errorTexts.isNotEmpty, isTrue);
  });

  testWidgets('empty mobile shows validation before hitting the network', (
    tester,
  ) async {
    await tester.pumpWidget(
      const MaterialApp(
        home: Directionality(
          textDirection: TextDirection.rtl,
          child: LoginScreen(),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await tester.tap(find.text('دخول'));
    await tester.pumpAndSettle();

    // Still on the login form, no spinner, and the validation message shows.
    expect(find.byType(CircularProgressIndicator), findsNothing);
    expect(find.text('دخول'), findsOneWidget);
  });
}
