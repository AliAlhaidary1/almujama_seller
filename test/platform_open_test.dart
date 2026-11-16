import 'package:flutter_test/flutter_test.dart';
import 'package:sareemart_seller/core/app_controller.dart';

void main() {
  group('platformOpen (business hours from backend settings)', () {
    test('whitespace opening/closing treated as unset (always open)', () {
      // The lab/backend stores empty business hours as a single space.
      // Backend treats them as always-open; the app must match.
      final app = AppController();
      app.settings = <String, dynamic>{
        'platform_opening_time': ' ',
        'platform_closing_time': ' ',
      };
      expect(app.platformOpen, isTrue);
    });

    test('empty opening/closing treated as unset (always open)', () {
      final app = AppController();
      app.settings = <String, dynamic>{};
      expect(app.platformOpen, isTrue);
    });

    test('equal concrete times mean always closed', () {
      final app = AppController();
      app.settings = <String, dynamic>{
        'platform_opening_time': '08:00',
        'platform_closing_time': '08:00',
      };
      expect(app.platformOpen, isFalse);
    });

    test('full-day window is always open', () {
      final app = AppController();
      app.settings = <String, dynamic>{
        'platform_opening_time': '00:00',
        'platform_closing_time': '23:59',
      };
      expect(app.platformOpen, isTrue);
    });

    test('padded times are trimmed like the backend', () {
      final app = AppController();
      app.settings = <String, dynamic>{
        'platform_opening_time': ' 08:00 ',
        'platform_closing_time': ' 08:00 ',
      };
      expect(app.platformOpen, isFalse);
    });
  });
}
