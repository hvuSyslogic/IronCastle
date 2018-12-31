using BouncyCastle.Core;
using BouncyCastle.Core.Port;
using org.bouncycastle.crypto.digests;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.agreement.jpake
{

		
	/// <summary>
	/// A participant in a Password Authenticated Key Exchange by Juggling (J-PAKE) exchange.
	/// <para>
	/// The J-PAKE exchange is defined by Feng Hao and Peter Ryan in the paper
	/// <a href="http://grouper.ieee.org/groups/1363/Research/contributions/hao-ryan-2008.pdf">
	/// "Password Authenticated Key Exchange by Juggling, 2008."</a>
	/// </para>
	/// <para>
	/// The J-PAKE protocol is symmetric.
	/// There is no notion of a <i>client</i> or <i>server</i>, but rather just two <i>participants</i>.
	/// An instance of <seealso cref="JPAKEParticipant"/> represents one participant, and
	/// is the primary interface for executing the exchange.
	/// </para>
	/// <para>
	/// To execute an exchange, construct a <seealso cref="JPAKEParticipant"/> on each end,
	/// and call the following 7 methods
	/// (once and only once, in the given order, for each participant, sending messages between them as described):
	/// <ol>
	/// <li><seealso cref="#createRound1PayloadToSend()"/> - and send the payload to the other participant</li>
	/// <li><seealso cref="#validateRound1PayloadReceived(JPAKERound1Payload)"/> - use the payload received from the other participant</li>
	/// <li><seealso cref="#createRound2PayloadToSend()"/> - and send the payload to the other participant</li>
	/// <li><seealso cref="#validateRound2PayloadReceived(JPAKERound2Payload)"/> - use the payload received from the other participant</li>
	/// <li><seealso cref="#calculateKeyingMaterial()"/></li>
	/// <li><seealso cref="#createRound3PayloadToSend(BigInteger)"/> - and send the payload to the other participant</li>
	/// <li><seealso cref="#validateRound3PayloadReceived(JPAKERound3Payload, BigInteger)"/> - use the payload received from the other participant</li>
	/// </ol>
	/// </para>
	/// <para>
	/// Each side should derive a session key from the keying material returned by <seealso cref="#calculateKeyingMaterial()"/>.
	/// The caller is responsible for deriving the session key using a secure key derivation function (KDF).
	/// </para>
	/// <para>
	/// Round 3 is an optional key confirmation process.
	/// If you do not execute round 3, then there is no assurance that both participants are using the same key.
	/// (i.e. if the participants used different passwords, then their session keys will differ.)
	/// </para>
	/// <para>
	/// If the round 3 validation succeeds, then the keys are guaranteed to be the same on both sides.
	/// </para>
	/// <para>
	/// The symmetric design can easily support the asymmetric cases when one party initiates the communication.
	/// e.g. Sometimes the round1 payload and round2 payload may be sent in one pass.
	/// Also, in some cases, the key confirmation payload can be sent together with the round2 payload.
	/// These are the trivial techniques to optimize the communication.
	/// </para>
	/// <para>
	/// The key confirmation process is implemented as specified in
	/// <a href="http://csrc.nist.gov/publications/nistpubs/800-56A/SP800-56A_Revision1_Mar08-2007.pdf">NIST SP 800-56A Revision 1</a>,
	/// Section 8.2 Unilateral Key Confirmation for Key Agreement Schemes.
	/// </para>
	/// <para>
	/// This class is stateful and NOT threadsafe.
	/// Each instance should only be used for ONE complete J-PAKE exchange
	/// (i.e. a new <seealso cref="JPAKEParticipant"/> should be constructed for each new J-PAKE exchange).
	/// </para>
	/// <para>
	/// </para>
	/// </summary>
	public class JPAKEParticipant
	{
		/*
		 * Possible internal states.  Used for state checking.
		 */

		public const int STATE_INITIALIZED = 0;
		public const int STATE_ROUND_1_CREATED = 10;
		public const int STATE_ROUND_1_VALIDATED = 20;
		public const int STATE_ROUND_2_CREATED = 30;
		public const int STATE_ROUND_2_VALIDATED = 40;
		public const int STATE_KEY_CALCULATED = 50;
		public const int STATE_ROUND_3_CREATED = 60;
		public const int STATE_ROUND_3_VALIDATED = 70;

		/// <summary>
		/// Unique identifier of this participant.
		/// The two participants in the exchange must NOT share the same id.
		/// </summary>
		private readonly string participantId;

		/// <summary>
		/// Shared secret.  This only contains the secret between construction
		/// and the call to <seealso cref="#calculateKeyingMaterial()"/>.
		/// <para>
		/// i.e. When <seealso cref="#calculateKeyingMaterial()"/> is called, this buffer overwritten with 0's,
		/// and the field is set to null.
		/// </para>
		/// </summary>
		private char[] password;

		/// <summary>
		/// Digest to use during calculations.
		/// </summary>
		private readonly Digest digest;

		/// <summary>
		/// Source of secure random data.
		/// </summary>
		private readonly SecureRandom random;

		private readonly BigInteger p;
		private readonly BigInteger q;
		private readonly BigInteger g;

		/// <summary>
		/// The participantId of the other participant in this exchange.
		/// </summary>
		private string partnerParticipantId;

		/// <summary>
		/// Alice's x1 or Bob's x3.
		/// </summary>
		private BigInteger x1;
		/// <summary>
		/// Alice's x2 or Bob's x4.
		/// </summary>
		private BigInteger x2;
		/// <summary>
		/// Alice's g^x1 or Bob's g^x3.
		/// </summary>
		private BigInteger gx1;
		/// <summary>
		/// Alice's g^x2 or Bob's g^x4.
		/// </summary>
		private BigInteger gx2;
		/// <summary>
		/// Alice's g^x3 or Bob's g^x1.
		/// </summary>
		private BigInteger gx3;
		/// <summary>
		/// Alice's g^x4 or Bob's g^x2.
		/// </summary>
		private BigInteger gx4;
		/// <summary>
		/// Alice's B or Bob's A.
		/// </summary>
		private BigInteger b;

		/// <summary>
		/// The current state.
		/// See the <tt>STATE_*</tt> constants for possible values.
		/// </summary>
		private int state;

		/// <summary>
		/// Convenience constructor for a new <seealso cref="JPAKEParticipant"/> that uses
		/// the <seealso cref="JPAKEPrimeOrderGroups#NIST_3072"/> prime order group,
		/// a SHA-256 digest, and a default <seealso cref="SecureRandom"/> implementation.
		/// <para>
		/// After construction, the <seealso cref="#getState() state"/> will be  <seealso cref="#STATE_INITIALIZED"/>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="participantId"> unique identifier of this participant.
		///                      The two participants in the exchange must NOT share the same id. </param>
		/// <param name="password">      shared secret.
		///                      A defensive copy of this array is made (and cleared once <seealso cref="#calculateKeyingMaterial()"/> is called).
		///                      Caller should clear the input password as soon as possible. </param>
		/// <exception cref="NullPointerException"> if any argument is null </exception>
		/// <exception cref="IllegalArgumentException"> if password is empty </exception>
		public JPAKEParticipant(string participantId, char[] password) : this(participantId, password, JPAKEPrimeOrderGroups.NIST_3072)
		{
		}


		/// <summary>
		/// Convenience constructor for a new <seealso cref="JPAKEParticipant"/> that uses
		/// a SHA-256 digest and a default <seealso cref="SecureRandom"/> implementation.
		/// <para>
		/// After construction, the <seealso cref="#getState() state"/> will be  <seealso cref="#STATE_INITIALIZED"/>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="participantId"> unique identifier of this participant.
		///                      The two participants in the exchange must NOT share the same id. </param>
		/// <param name="password">      shared secret.
		///                      A defensive copy of this array is made (and cleared once <seealso cref="#calculateKeyingMaterial()"/> is called).
		///                      Caller should clear the input password as soon as possible. </param>
		/// <param name="group">         prime order group.
		///                      See <seealso cref="JPAKEPrimeOrderGroups"/> for standard groups </param>
		/// <exception cref="NullPointerException"> if any argument is null </exception>
		/// <exception cref="IllegalArgumentException"> if password is empty </exception>
		public JPAKEParticipant(string participantId, char[] password, JPAKEPrimeOrderGroup group) : this(participantId, password, group, new SHA256Digest(), CryptoServicesRegistrar.getSecureRandom())
		{
		}


		/// <summary>
		/// Construct a new <seealso cref="JPAKEParticipant"/>.
		/// <para>
		/// After construction, the <seealso cref="#getState() state"/> will be  <seealso cref="#STATE_INITIALIZED"/>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="participantId"> unique identifier of this participant.
		///                      The two participants in the exchange must NOT share the same id. </param>
		/// <param name="password">      shared secret.
		///                      A defensive copy of this array is made (and cleared once <seealso cref="#calculateKeyingMaterial()"/> is called).
		///                      Caller should clear the input password as soon as possible. </param>
		/// <param name="group">         prime order group.
		///                      See <seealso cref="JPAKEPrimeOrderGroups"/> for standard groups </param>
		/// <param name="digest">        digest to use during zero knowledge proofs and key confirmation (SHA-256 or stronger preferred) </param>
		/// <param name="random">        source of secure random data for x1 and x2, and for the zero knowledge proofs </param>
		/// <exception cref="NullPointerException"> if any argument is null </exception>
		/// <exception cref="IllegalArgumentException"> if password is empty </exception>
		public JPAKEParticipant(string participantId, char[] password, JPAKEPrimeOrderGroup group, Digest digest, SecureRandom random)
		{
			JPAKEUtil.validateNotNull(participantId, "participantId");
			JPAKEUtil.validateNotNull(password, "password");
			JPAKEUtil.validateNotNull(group, "p");
			JPAKEUtil.validateNotNull(digest, "digest");
			JPAKEUtil.validateNotNull(random, "random");
			if (password.Length == 0)
			{
				throw new IllegalArgumentException("Password must not be empty.");
			}

			this.participantId = participantId;

			/*
			 * Create a defensive copy so as to fully encapsulate the password.
			 * 
			 * This array will contain the password for the lifetime of this
			 * participant BEFORE {@link #calculateKeyingMaterial()} is called.
			 * 
			 * i.e. When {@link #calculateKeyingMaterial()} is called, the array will be cleared
			 * in order to remove the password from memory.
			 * 
			 * The caller is responsible for clearing the original password array
			 * given as input to this constructor.
			 */
			this.password = Arrays.copyOf(password, password.Length);

			this.p = group.getP();
			this.q = group.getQ();
			this.g = group.getG();

			this.digest = digest;
			this.random = random;

			this.state = STATE_INITIALIZED;
		}

		/// <summary>
		/// Gets the current state of this participant.
		/// See the <tt>STATE_*</tt> constants for possible values.
		/// </summary>
		public virtual int getState()
		{
			return this.state;
		}

		/// <summary>
		/// Creates and returns the payload to send to the other participant during round 1.
		/// <para>
		/// After execution, the <seealso cref="#getState() state"/> will be  <seealso cref="#STATE_ROUND_1_CREATED"/>.
		/// </para>
		/// </summary>
		public virtual JPAKERound1Payload createRound1PayloadToSend()
		{
			if (this.state >= STATE_ROUND_1_CREATED)
			{
				throw new IllegalStateException("Round1 payload already created for " + participantId);
			}

			this.x1 = JPAKEUtil.generateX1(q, random);
			this.x2 = JPAKEUtil.generateX2(q, random);

			this.gx1 = JPAKEUtil.calculateGx(p, g, x1);
			this.gx2 = JPAKEUtil.calculateGx(p, g, x2);
			BigInteger[] knowledgeProofForX1 = JPAKEUtil.calculateZeroKnowledgeProof(p, q, g, gx1, x1, participantId, digest, random);
			BigInteger[] knowledgeProofForX2 = JPAKEUtil.calculateZeroKnowledgeProof(p, q, g, gx2, x2, participantId, digest, random);

			this.state = STATE_ROUND_1_CREATED;

			return new JPAKERound1Payload(participantId, gx1, gx2, knowledgeProofForX1, knowledgeProofForX2);
		}

		/// <summary>
		/// Validates the payload received from the other participant during round 1.
		/// <para>
		/// Must be called prior to <seealso cref="#createRound2PayloadToSend()"/>.
		/// </para>
		/// <para>
		/// After execution, the <seealso cref="#getState() state"/> will be  <seealso cref="#STATE_ROUND_1_VALIDATED"/>.
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="CryptoException"> if validation fails. </exception>
		/// <exception cref="IllegalStateException"> if called multiple times. </exception>
		public virtual void validateRound1PayloadReceived(JPAKERound1Payload round1PayloadReceived)
		{
			if (this.state >= STATE_ROUND_1_VALIDATED)
			{
				throw new IllegalStateException("Validation already attempted for round1 payload for" + participantId);
			}
			this.partnerParticipantId = round1PayloadReceived.getParticipantId();
			this.gx3 = round1PayloadReceived.getGx1();
			this.gx4 = round1PayloadReceived.getGx2();

			BigInteger[] knowledgeProofForX3 = round1PayloadReceived.getKnowledgeProofForX1();
			BigInteger[] knowledgeProofForX4 = round1PayloadReceived.getKnowledgeProofForX2();

			JPAKEUtil.validateParticipantIdsDiffer(participantId, round1PayloadReceived.getParticipantId());
			JPAKEUtil.validateGx4(gx4);
			JPAKEUtil.validateZeroKnowledgeProof(p, q, g, gx3, knowledgeProofForX3, round1PayloadReceived.getParticipantId(), digest);
			JPAKEUtil.validateZeroKnowledgeProof(p, q, g, gx4, knowledgeProofForX4, round1PayloadReceived.getParticipantId(), digest);

			this.state = STATE_ROUND_1_VALIDATED;
		}

		/// <summary>
		/// Creates and returns the payload to send to the other participant during round 2.
		/// <para>
		/// <seealso cref="#validateRound1PayloadReceived(JPAKERound1Payload)"/> must be called prior to this method.
		/// </para>
		/// <para>
		/// After execution, the <seealso cref="#getState() state"/> will be  <seealso cref="#STATE_ROUND_2_CREATED"/>.
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="IllegalStateException"> if called prior to <seealso cref="#validateRound1PayloadReceived(JPAKERound1Payload)"/>, or multiple times </exception>
		public virtual JPAKERound2Payload createRound2PayloadToSend()
		{
			if (this.state >= STATE_ROUND_2_CREATED)
			{
				throw new IllegalStateException("Round2 payload already created for " + this.participantId);
			}
			if (this.state < STATE_ROUND_1_VALIDATED)
			{
				throw new IllegalStateException("Round1 payload must be validated prior to creating Round2 payload for " + this.participantId);
			}
			BigInteger gA = JPAKEUtil.calculateGA(p, gx1, gx3, gx4);
			BigInteger s = JPAKEUtil.calculateS(password);
			BigInteger x2s = JPAKEUtil.calculateX2s(q, x2, s);
			BigInteger A = JPAKEUtil.calculateA(p, q, gA, x2s);
			BigInteger[] knowledgeProofForX2s = JPAKEUtil.calculateZeroKnowledgeProof(p, q, gA, A, x2s, participantId, digest, random);

			this.state = STATE_ROUND_2_CREATED;

			return new JPAKERound2Payload(participantId, A, knowledgeProofForX2s);
		}

		/// <summary>
		/// Validates the payload received from the other participant during round 2.
		/// <para>
		/// Note that this DOES NOT detect a non-common password.
		/// The only indication of a non-common password is through derivation
		/// of different keys (which can be detected explicitly by executing round 3 and round 4)
		/// </para>
		/// <para>
		/// Must be called prior to <seealso cref="#calculateKeyingMaterial()"/>.
		/// </para>
		/// <para>
		/// After execution, the <seealso cref="#getState() state"/> will be  <seealso cref="#STATE_ROUND_2_VALIDATED"/>.
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="CryptoException"> if validation fails. </exception>
		/// <exception cref="IllegalStateException"> if called prior to <seealso cref="#validateRound1PayloadReceived(JPAKERound1Payload)"/>, or multiple times </exception>
		public virtual void validateRound2PayloadReceived(JPAKERound2Payload round2PayloadReceived)
		{
			if (this.state >= STATE_ROUND_2_VALIDATED)
			{
				throw new IllegalStateException("Validation already attempted for round2 payload for" + participantId);
			}
			if (this.state < STATE_ROUND_1_VALIDATED)
			{
				throw new IllegalStateException("Round1 payload must be validated prior to validating Round2 payload for " + this.participantId);
			}
			BigInteger gB = JPAKEUtil.calculateGA(p, gx3, gx1, gx2);
			this.b = round2PayloadReceived.getA();
			BigInteger[] knowledgeProofForX4s = round2PayloadReceived.getKnowledgeProofForX2s();

			JPAKEUtil.validateParticipantIdsDiffer(participantId, round2PayloadReceived.getParticipantId());
			JPAKEUtil.validateParticipantIdsEqual(this.partnerParticipantId, round2PayloadReceived.getParticipantId());
			JPAKEUtil.validateGa(gB);
			JPAKEUtil.validateZeroKnowledgeProof(p, q, gB, b, knowledgeProofForX4s, round2PayloadReceived.getParticipantId(), digest);

			this.state = STATE_ROUND_2_VALIDATED;
		}

		/// <summary>
		/// Calculates and returns the key material.
		/// A session key must be derived from this key material using a secure key derivation function (KDF).
		/// The KDF used to derive the key is handled externally (i.e. not by <seealso cref="JPAKEParticipant"/>).
		/// <para>
		/// The keying material will be identical for each participant if and only if
		/// each participant's password is the same.  i.e. If the participants do not
		/// share the same password, then each participant will derive a different key.
		/// Therefore, if you immediately start using a key derived from
		/// the keying material, then you must handle detection of incorrect keys.
		/// If you want to handle this detection explicitly, you can optionally perform
		/// rounds 3 and 4.  See <seealso cref="JPAKEParticipant"/> for details on how to execute
		/// rounds 3 and 4.
		/// </para>
		/// <para>
		/// The keying material will be in the range <tt>[0, p-1]</tt>.
		/// </para>
		/// <para>
		/// <seealso cref="#validateRound2PayloadReceived(JPAKERound2Payload)"/> must be called prior to this method.
		/// </para>
		/// <para>
		/// As a side effect, the internal <seealso cref="#password"/> array is cleared, since it is no longer needed.
		/// </para>
		/// <para>
		/// After execution, the <seealso cref="#getState() state"/> will be  <seealso cref="#STATE_KEY_CALCULATED"/>.
		/// 
		/// </para>
		/// </summary>
		/// <exception cref="IllegalStateException"> if called prior to <seealso cref="#validateRound2PayloadReceived(JPAKERound2Payload)"/>,
		/// or if called multiple times. </exception>
		public virtual BigInteger calculateKeyingMaterial()
		{
			if (this.state >= STATE_KEY_CALCULATED)
			{
				throw new IllegalStateException("Key already calculated for " + participantId);
			}
			if (this.state < STATE_ROUND_2_VALIDATED)
			{
				throw new IllegalStateException("Round2 payload must be validated prior to creating key for " + participantId);
			}
			BigInteger s = JPAKEUtil.calculateS(password);

			/*
			 * Clear the password array from memory, since we don't need it anymore.
			 * 
			 * Also set the field to null as a flag to indicate that the key has already been calculated.
			 */
			Arrays.fill(password, (char)0);
			this.password = null;

			BigInteger keyingMaterial = JPAKEUtil.calculateKeyingMaterial(p, q, gx4, x2, s, b);

			/*
			 * Clear the ephemeral private key fields as well.
			 * Note that we're relying on the garbage collector to do its job to clean these up.
			 * The old objects will hang around in memory until the garbage collector destroys them.
			 * 
			 * If the ephemeral private keys x1 and x2 are leaked,
			 * the attacker might be able to brute-force the password.
			 */
			this.x1 = null;
			this.x2 = null;
			this.b = null;

			/*
			 * Do not clear gx* yet, since those are needed by round 3.
			 */

			this.state = STATE_KEY_CALCULATED;

			return keyingMaterial;
		}


		/// <summary>
		/// Creates and returns the payload to send to the other participant during round 3.
		/// <para>
		/// See <seealso cref="JPAKEParticipant"/> for more details on round 3.
		/// </para>
		/// <para>
		/// After execution, the <seealso cref="#getState() state"/> will be  <seealso cref="#STATE_ROUND_3_CREATED"/>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="keyingMaterial"> The keying material as returned from <seealso cref="#calculateKeyingMaterial()"/>. </param>
		/// <exception cref="IllegalStateException"> if called prior to <seealso cref="#calculateKeyingMaterial()"/>, or multiple times </exception>
		public virtual JPAKERound3Payload createRound3PayloadToSend(BigInteger keyingMaterial)
		{
			if (this.state >= STATE_ROUND_3_CREATED)
			{
				throw new IllegalStateException("Round3 payload already created for " + this.participantId);
			}
			if (this.state < STATE_KEY_CALCULATED)
			{
				throw new IllegalStateException("Keying material must be calculated prior to creating Round3 payload for " + this.participantId);
			}

			BigInteger macTag = JPAKEUtil.calculateMacTag(this.participantId, this.partnerParticipantId, this.gx1, this.gx2, this.gx3, this.gx4, keyingMaterial, this.digest);

			this.state = STATE_ROUND_3_CREATED;

			return new JPAKERound3Payload(participantId, macTag);
		}

		/// <summary>
		/// Validates the payload received from the other participant during round 3.
		/// <para>
		/// See <seealso cref="JPAKEParticipant"/> for more details on round 3.
		/// </para>
		/// <para>
		/// After execution, the <seealso cref="#getState() state"/> will be <seealso cref="#STATE_ROUND_3_VALIDATED"/>.
		/// 
		/// </para>
		/// </summary>
		/// <param name="round3PayloadReceived"> The round 3 payload received from the other participant. </param>
		/// <param name="keyingMaterial"> The keying material as returned from <seealso cref="#calculateKeyingMaterial()"/>. </param>
		/// <exception cref="CryptoException"> if validation fails. </exception>
		/// <exception cref="IllegalStateException"> if called prior to <seealso cref="#calculateKeyingMaterial()"/>, or multiple times </exception>
		public virtual void validateRound3PayloadReceived(JPAKERound3Payload round3PayloadReceived, BigInteger keyingMaterial)
		{
			if (this.state >= STATE_ROUND_3_VALIDATED)
			{
				throw new IllegalStateException("Validation already attempted for round3 payload for" + participantId);
			}
			if (this.state < STATE_KEY_CALCULATED)
			{
				throw new IllegalStateException("Keying material must be calculated validated prior to validating Round3 payload for " + this.participantId);
			}
			JPAKEUtil.validateParticipantIdsDiffer(participantId, round3PayloadReceived.getParticipantId());
			JPAKEUtil.validateParticipantIdsEqual(this.partnerParticipantId, round3PayloadReceived.getParticipantId());

			JPAKEUtil.validateMacTag(this.participantId, this.partnerParticipantId, this.gx1, this.gx2, this.gx3, this.gx4, keyingMaterial, this.digest, round3PayloadReceived.getMacTag());


			/*
			 * Clear the rest of the fields.
			 */
			this.gx1 = null;
			this.gx2 = null;
			this.gx3 = null;
			this.gx4 = null;

			this.state = STATE_ROUND_3_VALIDATED;
		}

	}

}