// SPDX-License-Identifier: BSD-3-Clause
// SPDX-FileCopyrightText: Z-Wave Alliance <https://z-wavealliance.org>
using System;
using System.Collections.Generic;
using System.Linq;
using ZWave;
using ZWave.BasicApplication;
using ZWave.BasicApplication.Operations;
using ZWave.Devices;
using static Zats.Services.AssociationGroupEx;

namespace Zats.Services
{
    /// <summary>
    /// Supporting node of the Wake On Critical Message Command Class (CC:008D).
    ///
    /// Each controlling node configures the maximum severity of the Notify Commands it accepts
    /// (CC:008D.01.01.11.002). The maximum severity is stored per controlling node (CC:008D.01.01.11.003),
    /// 0 by default (CC:008D.01.01.11.004), and erased by <see cref="ResetEmulation"/> on exclusion
    /// (CC:008D.01.00.21.00A).
    ///
    /// Configuration Set is ignored (Supervision status FAIL) if
    /// - it is received via multicast addressing (CC:008D.01.01.11.008),
    /// - it is not received at the highest granted Security Class (CC:008D.01.00.21.009),
    /// - the sender is not a Lifeline destination (CC:008D.01.01.11.006).
    /// Configuration Get is answered at any granted Security Class, since the Command Class is supported
    /// non-securely (in the NIF only, CC:008D.01.00.21.001/002 and CC:009F.01.00.21.00B), and ignored via
    /// multicast addressing (CC:008D.01.02.11.003). The Report carries the maximum severity of the requesting node.
    ///
    /// <see cref="SendCriticalMessage"/> sends a critical message in a Supervision Get to all Lifeline destinations.
    /// The Notify Command itself is added by the WakeOnCriticalMessageManager of the device.
    /// Received Notify Commands are the controlling side and not handled here.
    ///
    /// The Command Class must be supported non-securely: Secure and SecureExclusive must be false.
    /// On End Device libraries only non-secure critical messages are supported (see WakeOnCriticalMessageManager).
    /// </summary>
    [CommandClassName("Wake On Critical Message Command Class")]
    [CommandClassId(COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.ID)]
    [MinVersion(1)]
    [MaxVersion(1)]
    public class WakeOnCriticalMessageSupport : CommandClassSupport
    {
        private const byte MIN_SEVERITY = 1;
        private const byte MAX_SEVERITY = 7;

        private readonly object _maxSeveritiesLock = new object();
        private SvResultNames ResultForSv = SvResultNames.Undefined;

        private WakeOnCriticalMessageSupportData WakeOnCriticalMessageSupportData { get; set; }
        public override CommandClassSupportData CommandClassSupportData
        {
            get { return WakeOnCriticalMessageSupportData; }
            set { WakeOnCriticalMessageSupportData = (WakeOnCriticalMessageSupportData)value; }
        }

        public WakeOnCriticalMessageSupport()
            : this(new WakeOnCriticalMessageSupportData())
        { }

        public WakeOnCriticalMessageSupport(WakeOnCriticalMessageSupportData wakeOnCriticalMessageSupportData)
            : base(COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.ID)
        {
            WakeOnCriticalMessageSupportData = wakeOnCriticalMessageSupportData;
            // Supported non-securely: in the NIF, not in the S0/S2 Commands Supported Report (CC:008D.01.00.21.001/002).
            Secure = false;
            SecureExclusive = false;
        }

        /// <summary>
        /// Maximum severity the given controlling node has configured, 0 if it has configured none.
        /// The End Point of the node is ignored: the maximum severity is stored per node.
        /// </summary>
        public byte GetMaxSeverity(NodeTag controllingNode)
        {
            return GetMaxSeverity(controllingNode.Id);
        }

        /// <summary>
        /// Sends a critical message to all Lifeline destinations, encapsulated in a Supervision Get
        /// (CC:008D.01.04.11.012):
        /// - A destination with a configured maximum severity gets it in a Notify Command, with the severity of the
        ///   message clamped to the maximum severity of the destination (CC:008D.01.04.11.003).
        /// - A destination without a configured maximum severity gets no Notify Command (CC:008D.01.04.11.001), but the
        ///   message without it, or nothing if WakeOnCriticalMessageSupportData.SkipUnconfiguredDestinations is set.
        /// The Supervision Get is built here with the Session ID counter of the device; the Supervision manager of the
        /// device is required to process the Supervision Report. Sent at the highest granted Security Class.
        /// </summary>
        /// <param name="command">critical message, e.g. a Notification Report (max. 39 bytes incl. encapsulation, CC:008D.01.00.21.004)</param>
        /// <param name="severity">severity of the message itself (1..7), before clamping</param>
        /// <returns>true if the message was sent to all destinations it is meant for, false if sending failed for any of them</returns>
        /// <exception cref="ArgumentOutOfRangeException">severity not in range 1..7</exception>
        /// <exception cref="ArgumentException">command shorter than 2 bytes</exception>
        /// <exception cref="InvalidOperationException">supporting device not set up, not included, or without Supervision/Settings manager</exception>
        public bool SendCriticalMessage(byte[] command, byte severity)
        {
            if (severity < MIN_SEVERITY || severity > MAX_SEVERITY)
            {
                throw new ArgumentOutOfRangeException(nameof(severity), severity,
                    "The severity of a critical message must be in range 1..7 (CC:008D.01.04.11.004). " +
                    "Use SendDataSettings.SetWakeOnCriticalMessageSeverity for negative testing.");
            }
            if (command == null || command.Length < 2)
            {
                throw new ArgumentException("The critical message must contain at least Command Class and Command.", nameof(command));
            }
            // Setup errors of the test case: thrown, so that false only means that sending failed.
            if (ReportDevice == null || _network.NodeTag == NodeTag.Empty)
            {
                throw new InvalidOperationException("Critical message not sent: the supporting device is not set up or not included.");
            }
            // The Supervision manager does not encapsulate (it only wraps multicast follow-ups), but it is needed to
            // process the Supervision Report the destination sends back.
            if (ReportDevice.SessionClient.GetSubstituteManager(typeof(SupervisionManager)) == null)
            {
                throw new InvalidOperationException("Critical message not sent: the supporting device has no Supervision manager (set it up with supervision).");
            }
            var settingsManager = (SettingsSubstituteManager)ReportDevice.SessionClient.GetSubstituteManager(typeof(SettingsSubstituteManager));
            if (settingsManager == null)
            {
                throw new InvalidOperationException("Critical message not sent: the supporting device has no Settings manager (no Supervision Session ID available).");
            }

            bool ret = true;
            ZWave.Enums.SecuritySchemes scheme = ReportDevice.Network.GetHighestSecurityScheme();
            foreach (NodeIdEx destination in GetLifelineNodes())
            {
                byte maxSeverity = GetMaxSeverity(destination.NodeId);
                if (maxSeverity == 0 && WakeOnCriticalMessageSupportData.SkipUnconfiguredDestinations)
                {
                    LogInfo($"Critical message skipped for Node {destination.NodeId}: no maximum severity configured");
                    continue;
                }

                // The Notify Command must carry a Supervision Get (CC:008D.01.04.11.012), so the message is always
                // encapsulated here, also for destinations without Notify Command.
                byte sessionId = NextSupervisionSessionId(settingsManager.SendDataDeviceSettings);
                byte[] supervisionGet = new COMMAND_CLASS_SUPERVISION.SUPERVISION_GET
                {
                    properties1 = new COMMAND_CLASS_SUPERVISION.SUPERVISION_GET.Tproperties1 { sessionId = sessionId, statusUpdates = 0 },
                    encapsulatedCommandLength = (byte)command.Length,
                    encapsulatedCommand = command
                };

                var substituteSettings = new SubstituteSettings(ZWave.Enums.SubstituteFlags.None, 0);
                if (maxSeverity > 0)
                {
                    substituteSettings.WakeOnCriticalMessageSeverity = Math.Min(severity, maxSeverity);
                }

                var destinationNode = new NodeTag(destination.NodeId);
                var result = ReportDevice.SendDataEx(destinationNode, supervisionGet, TxOptions, substituteSettings, TxSecOptions, scheme, TxOptions2);
                bool isSent = result != null && result.State == ActionStates.Completed;
                ret &= isSent;
                LogInfo($"Critical message to Node {destination.NodeId} in a Supervision Get (Session ID {sessionId}) " +
                    (maxSeverity > 0
                        ? $"in a Notify Command with Severity {substituteSettings.WakeOnCriticalMessageSeverity} (maximum severity {maxSeverity})"
                        : "without Notify Command (no maximum severity configured)") +
                    (isSent ? " sent" : " failed!"));
            }
            return ret;
        }

        /// <summary>
        /// Next Supervision Session ID of the device. The counter of the send settings is shared with
        /// ComplianceService (SendDataSettings.Get/SetSessionID), so supervised frames of the same device never repeat
        /// a Session ID back to back, which the receiver may discard as a duplicate. It is always incremented here,
        /// regardless of SendDataSettings.SetAutoIncrement, since the emulated device must behave correctly.
        /// </summary>
        private static byte NextSupervisionSessionId(SendDataDeviceSettings settings)
        {
            lock (settings)
            {
                // The Session ID field has 6 bits.
                settings.SessionID = (byte)((settings.SessionID + 1) & 0x3F);
                return settings.SessionID;
            }
        }

        public override void ResetEmulation()
        {
            lock (_maxSeveritiesLock)
            {
                WakeOnCriticalMessageSupportData.MaxSeverities.Clear();
            }
            SupportDelegates?.DeviceDataUpdate?.Invoke(this);
        }

        protected override void OnHandledDelayed(DataReceivedUnit ou)
        {
            ou.SetNextActionItems();

            // Only the Root Device supports the Command Class: the Notify Command must not be encapsulated (CC:008D.01.00.21.003).
            if (EndPoint != 0 || !MatchesDestinationEndPoint())
            {
                return;
            }

            var sendDstNode = new NodeTag(ReceivedAchData.DstNode.Id, DstNode.EndPointId);
            var sendSrcNode = ReceivedAchData.SrcNode;
            byte[] command = ReceivedAchData.Command;
            var scheme = ReceivedAchData.SecurityScheme;
            bool isHandlingAllowed = IsHandlingAllowed(Network, command, scheme, Secure);

            ResultForSv = SvResultNames.Undefined;
            if (isHandlingAllowed && command != null && command.Length > 1 && WakeOnCriticalMessageSupportData != null)
            {
                byte[] rpt = null;
                if (command[1] == COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_CONFIGURATION_SET.ID)
                {
                    ResultForSv = HandleConfigurationSet(command, sendSrcNode, scheme);
                }
                else if (command[1] == COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_CONFIGURATION_GET.ID && !IsSupervised())
                {
                    // Answered at any granted Security Class, but not via multicast addressing (CC:008D.01.02.11.003).
                    rpt = PrepareConfigurationReport(sendSrcNode);
                }

                if (rpt != null && IsAnsweringAllowed())
                {
                    ApiOperation sendData = new SendDataExOperation(_network, sendDstNode, sendSrcNode, rpt, TxOptions, TxSecOptions, scheme, TxOptions2);
                    ou.SetNextActionItems(sendData);
                }

                CommandCallback(command, sendDstNode.EndPointId);
            }
        }

        private SvResultNames HandleConfigurationSet(byte[] command, NodeTag srcNode, ZWave.Enums.SecuritySchemes scheme)
        {
            if (command.Length < 3)
            {
                LogInfo("Configuration Set ignored: command too short");
                return SvResultNames.Failed;
            }
            if (!IsAnsweringAllowed())
            {
                LogInfo("Configuration Set ignored: received via multicast addressing (CC:008D.01.01.11.008)");
                return SvResultNames.Failed;
            }
            if (scheme != Network.GetHighestSecurityScheme())
            {
                LogInfo($"Configuration Set ignored: received with {scheme}, highest granted is {Network.GetHighestSecurityScheme()} (CC:008D.01.00.21.009)");
                return SvResultNames.Failed;
            }
            if (!GetLifelineNodes().Any(x => x.NodeId == srcNode.Id))
            {
                LogInfo($"Configuration Set ignored: Node {srcNode.Id} is not a Lifeline destination (CC:008D.01.01.11.006)");
                return SvResultNames.Failed;
            }

            // The generated type ignores the Reserved bits (CC:008D.01.01.11.001).
            COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_CONFIGURATION_SET set = command;
            byte maxSeverity = set.properties1.severity;
            lock (_maxSeveritiesLock)
            {
                WakeOnCriticalMessageSupportData.MaxSeverities[srcNode.Id] = maxSeverity;
            }
            LogInfo($"Maximum severity of Node {srcNode.Id} set to {maxSeverity}");
            SupportDelegates?.DeviceDataUpdate?.Invoke(this);
            return SvResultNames.Successful;
        }

        private byte[] PrepareConfigurationReport(NodeTag srcNode)
        {
            // The Report carries the maximum severity of the node to which it is sent.
            var rpt = new COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_CONFIGURATION_REPORT();
            rpt.properties1.severity = GetMaxSeverity(srcNode.Id);
            return rpt;
        }

        private byte GetMaxSeverity(ushort nodeId)
        {
            lock (_maxSeveritiesLock)
            {
                return WakeOnCriticalMessageSupportData.MaxSeverities.TryGetValue(nodeId, out byte maxSeverity) ? maxSeverity : (byte)0;
            }
        }

        public override void SupervisionCallback(COMMAND_CLASS_SUPERVISION.SUPERVISION_GET supervisionGet,
                                                 COMMAND_CLASS_SUPERVISION.SUPERVISION_REPORT supervisionReport)
        {
            if (ResultForSv == SvResultNames.Undefined || supervisionGet.encapsulatedCommand[0] != CommandClassId)
            {
                supervisionReport.status = (byte)SvStatusNames.NoSupport;
                return;
            }

            supervisionReport.status = (byte)SvStatusNames.Fail;
            if (supervisionGet.encapsulatedCommand[1] == COMMAND_CLASS_WAKE_ON_CRITICAL_MESSAGE.WAKE_ON_CRITICAL_MESSAGE_CONFIGURATION_SET.ID &&
                ResultForSv == SvResultNames.Successful)
            {
                supervisionReport.status = (byte)SvStatusNames.Success;
            }
            ResultForSv = SvResultNames.Undefined;
        }

        public override void UpdateSupportData(CommandClassSupportData data)
        {
            if (data is WakeOnCriticalMessageSupportData newData)
            {
                lock (_maxSeveritiesLock)
                {
                    WakeOnCriticalMessageSupportData.MaxSeverities = new Dictionary<ushort, byte>(newData.MaxSeverities);
                }
                WakeOnCriticalMessageSupportData.SkipUnconfiguredDestinations = newData.SkipUnconfiguredDestinations;
                SupportDelegates?.DeviceDataUpdate?.Invoke(this);
            }
        }

        // Logged into the test report like the other supports, only if WakeOnCriticalMessageSupportData.LogLevel > 0.
        private void LogInfo(string message)
        {
            CommandClassSupportUtils.ReportAddLog(WakeOnCriticalMessageSupportData.LogLevel, "{0} CC @ {1}: {2}",
                CommandClassShortName, EndPointName, message);
        }
    }

    public class WakeOnCriticalMessageSupportData : CommandClassSupportData
    {
        /// <summary>
        /// Maximum severity per controlling node (Node ID), as configured with the Configuration Set Command.
        /// A node without entry has configured none (0): it gets no Notify Command (CC:008D.01.04.11.001).
        /// </summary>
        public Dictionary<ushort, byte> MaxSeverities { get; set; } = new Dictionary<ushort, byte>();

        /// <summary>
        /// If true, SendCriticalMessage skips Lifeline destinations without a configured maximum severity;
        /// otherwise they get the message without Notify Command (default).
        /// </summary>
        public bool SkipUnconfiguredDestinations { get; set; } = false;
    }
}
