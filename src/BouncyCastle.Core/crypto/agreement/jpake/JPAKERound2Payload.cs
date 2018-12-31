using BouncyCastle.Core.Port;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.agreement.jpake
{

	
	/// <summary>
	/// The payload sent/received during the second round of a J-PAKE exchange.
	/// <para>
	/// Each <seealso cref="JPAKEParticipant"/> creates and sends an instance
	/// of this payload to the other <seealso cref="JPAKEParticipant"/>.
	/// The payload to send should be created via
	/// <seealso cref="JPAKEParticipant#createRound2PayloadToSend()"/>
	/// </para>
	/// <para>
	/// Each <seealso cref="JPAKEParticipant"/> must also validate the payload
	/// received from the other <seealso cref="JPAKEParticipant"/>.
	/// The received payload should be validated via
	/// <seealso cref="JPAKEParticipant#validateRound2PayloadReceived(JPAKERound2Payload)"/>
	/// </para>
	/// </summary>
	public class JPAKERound2Payload
	{
		/// <summary>
		/// The id of the <seealso cref="JPAKEParticipant"/> who created/sent this payload.
		/// </summary>
		private readonly string participantId;

		/// <summary>
		/// The value of A, as computed during round 2.
		/// </summary>
		private readonly BigInteger a;

		/// <summary>
		/// The zero knowledge proof for x2 * s.
		/// <para>
		/// This is a two element array, containing {g^v, r} for x2 * s.
		/// </para>
		/// </summary>
		private readonly BigInteger[] knowledgeProofForX2s;

		public JPAKERound2Payload(string participantId, BigInteger a, BigInteger[] knowledgeProofForX2s)
		{
			JPAKEUtil.validateNotNull(participantId, "participantId");
			JPAKEUtil.validateNotNull(a, "a");
			JPAKEUtil.validateNotNull(knowledgeProofForX2s, "knowledgeProofForX2s");

			this.participantId = participantId;
			this.a = a;
			this.knowledgeProofForX2s = Arrays.copyOf(knowledgeProofForX2s, knowledgeProofForX2s.Length);
		}

		public virtual string getParticipantId()
		{
			return participantId;
		}

		public virtual BigInteger getA()
		{
			return a;
		}

		public virtual BigInteger[] getKnowledgeProofForX2s()
		{
			return Arrays.copyOf(knowledgeProofForX2s, knowledgeProofForX2s.Length);
		}

	}

}