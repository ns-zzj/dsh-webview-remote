// DshRemoteApp 的冒烟测试。
//
// 只验证【连接表单能正常构建】—— 这是纯 UI，跑得起来就说明没有低级错误。
//
// 刻意【不测】认证流程和 WebView：那两样都要真机 + 真网关才能验，
// 在单元测试里 mock 出来只会给人「已经验过了」的错觉。
// 相关未验证项见 开发思路.md。

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:dsh_webview_remote_client/main.dart';

void main() {
  testWidgets('连接表单渲染出标题、两个输入框和连接按钮', (WidgetTester tester) async {
    await tester.pumpWidget(const DshRemoteApp());

    // 断言用 kAppTitle，**不要写死字符串** ——
    // 应用名改过一次（DSH 远程 → DSH WebView 远程客户端）。写死的话这个测试
    // 会跟着烂，而且烂得很隐蔽：只有跑 test 才看得到。
    expect(find.text(kAppTitle), findsOneWidget);
    expect(find.text('网关地址'), findsOneWidget);
    expect(find.text('密码'), findsOneWidget);
    expect(find.text('连接'), findsOneWidget);

    // 密码字段必须是遮蔽的 —— 需求明确「密码只留在内存里」，
    // 界面上就不该把它显示出来。
    expect(
      find.byWidgetPredicate((widget) => widget is TextField && widget.obscureText),
      findsOneWidget,
    );
  });
}
