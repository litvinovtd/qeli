# Шаблоны управляемого развёртывания iOS

Русский · [English](../../eng/manuals/IOS-MDM.md)

Файлы в [`qeli-ios/MDM`](../../../qeli-ios/MDM/) — шаблоны администратора,
а не функции обычного consumer-приложения. Перед развёртыванием проверьте и
подпишите изменённые профили средствами MDM. Замените все примерные bundle ID,
UUID, серверы, идентификаторы профилей и учётные данные.

## Qeli Per-App VPN

[`Qeli-PerApp-VPN.mobileconfig`](../../../qeli-ios/MDM/Qeli-PerApp-VPN.mobileconfig)
использует payload Apple `com.apple.vpn.managed.applayer` и Packet Tunnel Provider
Qeli. Идентификаторы должны соответствовать
[`Config/Signing.xcconfig`](../../../qeli-ios/Config/Signing.xcconfig):

- `VPNSubType` — bundle ID содержащего приложения Qeli (`QELI_APP_BUNDLE_ID`).
- `VPN.ProviderBundleIdentifier` — `QELI_TUNNEL_BUNDLE_ID`.
- `VPNUUID` — постоянный UUID, назначаемый MDM каждому управляемому приложению.
- `VendorConfig.profileID` — UUID профиля, уже существующего в шифрованном
  App Group store Qeli. Пример не доставляет учётные данные или текст профиля.

На iOS целевое приложение также должно быть управляемым. Свяжите его с VPN,
задав тот же `VPNUUID` в атрибутах приложения. Фрагмент MDM `InstallApplication`:

```xml
<key>Attributes</key>
<dict>
    <key>VPNUUID</key>
    <string>1653840A-E082-4CC2-877A-A8D188C183B6</string>
</dict>
```

Declarative Device Management использует эквивалентное свойство
`Attributes.VPNUUID` в декларации управляемого приложения. Обычная установка
App Store не позволяет назначить произвольные приложения этому VPN; Qeli
не пытается перечислять установленные приложения.

Документация Apple:

- https://developer.apple.com/documentation/devicemanagement/applayervpn
- https://developer.apple.com/documentation/devicemanagement/installapplicationcommand/command-data.dictionary/attributes-data.dictionary

## Always On VPN

[`Apple-IKEv2-AlwaysOn.mobileconfig`](../../../qeli-ios/MDM/Apple-IKEv2-AlwaysOn.mobileconfig)
описывает настоящий механизм Apple Always On. Он требует supervised-устройства,
управляемого через MDM, и сервера IKEv2. Этот шаблон **не** делает собственный
Packet Tunnel Provider Qeli Always On и несовместим с wire-протоколом Qeli.
На обычных устройствах используйте настройку VPN On Demand в Qeli.

Placeholder общего секрета делает пример самодостаточным, но для организации
предпочтительна аутентификация сертификатом с отдельно доставленным identity
payload. Не развёртывайте placeholder secret и имена хостов `.invalid`.

Документация Apple:

- https://support.apple.com/guide/deployment/depae3d361d0/web
- https://developer.apple.com/documentation/devicemanagement/vpn
- https://developer.apple.com/documentation/devicemanagement/vpn/alwayson-data.dictionary

## Управляемая конфигурация приложения

[`Qeli-Managed-App-Configuration.plist`](../../../qeli-ios/MDM/Qeli-Managed-App-Configuration.plist)
— словарь legacy managed app configuration, а не configuration profile.
`ManagedConfigurationReader` Qeli читает его из
`UserDefaults.standard["com.apple.configuration.managed"]` и принимает:

- `configurationVersion` — точную представимую целочисленную версию схемы;
  Boolean, дробные значения и переполнение отклоняются.
- `activeProfileID` — строку UUID существующего шифрованного профиля.
- `onDemandEnabled` — Boolean policy value.
- `widgetControlsEnabled` — Boolean policy value.

Принимаются настоящие Boolean и legacy точные числовые 0/1. Дробные,
нефинитные и неверно типизированные policy values игнорируются без усечения.
Число 1.0 остаётся точным целочисленным значением.

Reader не имеет побочных эффектов. При запуске и каждом переходе приложения
в активное состояние `AppModel` отдаёт приоритет managed values: выбирает профиль
для следующего подключения, применяет managed On Demand и переносит политику
widget controls в App Group, чтобы расширение могло отказать запрещённому действию.
Некорректный `activeProfileID` или UUID без соответствующего локального профиля
приводит к безопасному отказу: Qeli блокирует ручной запуск и виджет, останавливает
прежний туннель, удаляет On Demand rules и отключает устаревшую provider configuration.
Текст профиля, пароли и private keys не принимаются. В новых managed deployments
Apple ManagedApp framework может заменить legacy доставку через `UserDefaults`.

### Порядок первоначальной настройки

Политика содержит ссылку на UUID, а не сам профиль. Он должен существовать
на устройстве **до** получения политики; порядок шагов существенен:

1. Установите Qeli как **управляемое** приложение. Legacy managed app configuration
   получают приложения, установленные MDM; sideloaded/App Store copies ключ не видят.
2. Доставьте профиль и сохраните его UUID. Qeli намеренно не принимает текст,
   пароль или ключ через MDM: используйте `qeli://`, QR либо INI import, выполненный
   пользователем или подготовленный вместе с Per-App VPN payload.
3. Затем доставьте словарь с `activeProfileID`, равным этому UUID.

Доставка шага 3 первой — типичная ошибка. Несуществующий UUID считается нарушением
политики, а не её отсутствием: блокируются ручной запуск и виджет, работающий
туннель останавливается, On Demand rules удаляются, старая provider configuration
отключается. Управляемое устройство не должно незаметно переключаться на профиль,
выбранный пользователем, но неверный порядок развёртывания выглядит как отказ приложения.

### Откат

Удалите managed configuration или только `activeProfileID`: управление вернётся
пользователю, приложение выберет локальный профиль, а заданное политикой значение
On Demand уступит собственной настройке приложения. Удаление политики **не**
удаляет профили, credentials или provider configuration, а прекращает их навязывание.

При окончательной передаче устройства сначала удалите политику и проверьте
подключение локального профиля, затем снимайте управление или удаляйте приложение.
Обратный порядок оставляет последнее принудительное состояние без механизма снятия.

Документация Apple:

- https://developer.apple.com/documentation/devicemanagement/configuring-managed-apps-and-extensions
