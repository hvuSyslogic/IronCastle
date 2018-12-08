using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.agreement.jpake
{

	/// <summary>
	/// The payload sent/received during the optional third round of a J-PAKE exchange,
	/// which is for explicit key confirmation.
	/// <para>
	/// Each <seealso cref="JPAKEParticipant"/> creates and sends an instance
	/// of this payload to the other <seealso cref="JPAKEParticipant"/>.
	/// The payload to send should be created via
	/// <seealso cref="JPAKEParticipant#createRound3PayloadToSend(BigInteger)"/>
	/// </para>
	/// <para>
	/// Each <seealso cref="JPAKEParticipant"/> must also validate the payload
	/// received from the other <seealso cref="JPAKEParticipant"/>.
	/// The received payload should be validated via
	/// <seealso cref="JPAKEParticipant#validateRound3PayloadReceived(JPAKERound3Payload, BigInteger)"/>
	/// </para>
	/// </summary>
	public class JPAKERound3Payload
	{
		/// <summary>
		/// The id of the <seealso cref="JPAKEParticipant"/> who created/sent this payload.
		/// </summary>
		private readonly string participantId;

		/// <summary>
		/// The value of MacTag, as computed by round 3.
		/// </summary>
		/// <seealso cref= JPAKEUtil#calculateMacTag(String, String, BigInteger, BigInteger, BigInteger, BigInteger, BigInteger, org.bouncycastle.crypto.Digest) </seealso>
		private readonly BigInteger macTag;

		public JPAKERound3Payload(string participantId, BigInteger magTag)
		{
			this.participantId = participantId;
			this.macTag = magTag;
		}

		public virtual string getParticipantId()
		{
			return participantId;
		}

		public virtual BigInteger getMacTag()
		{
			return macTag;
		}

	}

}