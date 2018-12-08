using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.agreement.jpake
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// The payload sent/received during the first round of a J-PAKE exchange.
	/// <para>
	/// Each <seealso cref="JPAKEParticipant"/> creates and sends an instance
	/// of this payload to the other <seealso cref="JPAKEParticipant"/>.
	/// The payload to send should be created via
	/// <seealso cref="JPAKEParticipant#createRound1PayloadToSend()"/>.
	/// </para>
	/// <para>
	/// Each <seealso cref="JPAKEParticipant"/> must also validate the payload
	/// received from the other <seealso cref="JPAKEParticipant"/>.
	/// The received payload should be validated via
	/// <seealso cref="JPAKEParticipant#validateRound1PayloadReceived(JPAKERound1Payload)"/>.
	/// </para>
	/// </summary>
	public class JPAKERound1Payload
	{
		/// <summary>
		/// The id of the <seealso cref="JPAKEParticipant"/> who created/sent this payload.
		/// </summary>
		private readonly string participantId;

		/// <summary>
		/// The value of g^x1
		/// </summary>
		private readonly BigInteger gx1;

		/// <summary>
		/// The value of g^x2
		/// </summary>
		private readonly BigInteger gx2;

		/// <summary>
		/// The zero knowledge proof for x1.
		/// <para>
		/// This is a two element array, containing {g^v, r} for x1.
		/// </para>
		/// </summary>
		private readonly BigInteger[] knowledgeProofForX1;

		/// <summary>
		/// The zero knowledge proof for x2.
		/// <para>
		/// This is a two element array, containing {g^v, r} for x2.
		/// </para>
		/// </summary>
		private readonly BigInteger[] knowledgeProofForX2;

		public JPAKERound1Payload(string participantId, BigInteger gx1, BigInteger gx2, BigInteger[] knowledgeProofForX1, BigInteger[] knowledgeProofForX2)
		{
			JPAKEUtil.validateNotNull(participantId, "participantId");
			JPAKEUtil.validateNotNull(gx1, "gx1");
			JPAKEUtil.validateNotNull(gx2, "gx2");
			JPAKEUtil.validateNotNull(knowledgeProofForX1, "knowledgeProofForX1");
			JPAKEUtil.validateNotNull(knowledgeProofForX2, "knowledgeProofForX2");

			this.participantId = participantId;
			this.gx1 = gx1;
			this.gx2 = gx2;
			this.knowledgeProofForX1 = Arrays.copyOf(knowledgeProofForX1, knowledgeProofForX1.Length);
			this.knowledgeProofForX2 = Arrays.copyOf(knowledgeProofForX2, knowledgeProofForX2.Length);
		}

		public virtual string getParticipantId()
		{
			return participantId;
		}

		public virtual BigInteger getGx1()
		{
			return gx1;
		}

		public virtual BigInteger getGx2()
		{
			return gx2;
		}

		public virtual BigInteger[] getKnowledgeProofForX1()
		{
			return Arrays.copyOf(knowledgeProofForX1, knowledgeProofForX1.Length);
		}

		public virtual BigInteger[] getKnowledgeProofForX2()
		{
			return Arrays.copyOf(knowledgeProofForX2, knowledgeProofForX2.Length);
		}

	}

}