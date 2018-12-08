using BouncyCastle.Core.Port;
using org.bouncycastle.Port;

namespace org.bouncycastle.crypto.examples
{

	using JPAKEPrimeOrderGroup = org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroup;
	using JPAKEPrimeOrderGroups = org.bouncycastle.crypto.agreement.jpake.JPAKEPrimeOrderGroups;
	using JPAKEParticipant = org.bouncycastle.crypto.agreement.jpake.JPAKEParticipant;
	using JPAKERound1Payload = org.bouncycastle.crypto.agreement.jpake.JPAKERound1Payload;
	using JPAKERound2Payload = org.bouncycastle.crypto.agreement.jpake.JPAKERound2Payload;
	using JPAKERound3Payload = org.bouncycastle.crypto.agreement.jpake.JPAKERound3Payload;
	using SHA256Digest = org.bouncycastle.crypto.digests.SHA256Digest;

	/// <summary>
	/// An example of a J-PAKE exchange.
	/// <para>
	/// 
	/// In this example, both Alice and Bob are on the same computer (in the same JVM, in fact).
	/// In reality, Alice and Bob would be in different locations,
	/// and would be sending their generated payloads to each other.
	/// </para>
	/// </summary>
	public class JPAKEExample
	{

		public static void Main(string[] args)
		{
			/*
			 * Initialization
			 * 
			 * Pick an appropriate prime order group to use throughout the exchange.
			 * Note that both participants must use the same group.
			 */
			JPAKEPrimeOrderGroup group = JPAKEPrimeOrderGroups.NIST_3072;

			BigInteger p = group.getP();
			BigInteger q = group.getQ();
			BigInteger g = group.getG();

			string alicePassword = "password";
			string bobPassword = "password";

			JavaSystem.@out.println("********* Initialization **********");
			JavaSystem.@out.println("Public parameters for the cyclic group:");
			JavaSystem.@out.println("p (" + p.bitLength() + " bits): " + p.ToString(16));
			JavaSystem.@out.println("q (" + q.bitLength() + " bits): " + q.ToString(16));
			JavaSystem.@out.println("g (" + p.bitLength() + " bits): " + g.ToString(16));
			JavaSystem.@out.println("p mod q = " + p.mod(q).ToString(16));
			JavaSystem.@out.println("g^{q} mod p = " + g.modPow(q, p).ToString(16));
			JavaSystem.@out.println("");

			JavaSystem.@out.println("(Secret passwords used by Alice and Bob: " + @"""" + alicePassword + @""" and """ + bobPassword + @""")\n");

			/*
			 * Both participants must use the same hashing algorithm.
			 */
			Digest digest = new SHA256Digest();
			SecureRandom random = new SecureRandom();

			JPAKEParticipant alice = new JPAKEParticipant("alice", alicePassword.ToCharArray(), group, digest, random);
			JPAKEParticipant bob = new JPAKEParticipant("bob", bobPassword.ToCharArray(), group, digest, random);

			/*
			 * Round 1
			 * 
			 * Alice and Bob each generate a round 1 payload, and send it to each other.
			 */

			JPAKERound1Payload aliceRound1Payload = alice.createRound1PayloadToSend();
			JPAKERound1Payload bobRound1Payload = bob.createRound1PayloadToSend();

			JavaSystem.@out.println("************ Round 1 **************");
			JavaSystem.@out.println("Alice sends to Bob: ");
			JavaSystem.@out.println("g^{x1}=" + aliceRound1Payload.getGx1().ToString(16));
			JavaSystem.@out.println("g^{x2}=" + aliceRound1Payload.getGx2().ToString(16));
			JavaSystem.@out.println("KP{x1}={" + aliceRound1Payload.getKnowledgeProofForX1()[0].ToString(16) + "};{" + aliceRound1Payload.getKnowledgeProofForX1()[1].ToString(16) + "}");
			JavaSystem.@out.println("KP{x2}={" + aliceRound1Payload.getKnowledgeProofForX2()[0].ToString(16) + "};{" + aliceRound1Payload.getKnowledgeProofForX2()[1].ToString(16) + "}");
			JavaSystem.@out.println("");

			JavaSystem.@out.println("Bob sends to Alice: ");
			JavaSystem.@out.println("g^{x3}=" + bobRound1Payload.getGx1().ToString(16));
			JavaSystem.@out.println("g^{x4}=" + bobRound1Payload.getGx2().ToString(16));
			JavaSystem.@out.println("KP{x3}={" + bobRound1Payload.getKnowledgeProofForX1()[0].ToString(16) + "};{" + bobRound1Payload.getKnowledgeProofForX1()[1].ToString(16) + "}");
			JavaSystem.@out.println("KP{x4}={" + bobRound1Payload.getKnowledgeProofForX2()[0].ToString(16) + "};{" + bobRound1Payload.getKnowledgeProofForX2()[1].ToString(16) + "}");
			JavaSystem.@out.println("");

			/*
			 * Each participant must then validate the received payload for round 1
			 */

			alice.validateRound1PayloadReceived(bobRound1Payload);
			JavaSystem.@out.println("Alice checks g^{x4}!=1: OK");
			JavaSystem.@out.println("Alice checks KP{x3}: OK");
			JavaSystem.@out.println("Alice checks KP{x4}: OK");
			JavaSystem.@out.println("");

			bob.validateRound1PayloadReceived(aliceRound1Payload);
			JavaSystem.@out.println("Bob checks g^{x2}!=1: OK");
			JavaSystem.@out.println("Bob checks KP{x1},: OK");
			JavaSystem.@out.println("Bob checks KP{x2},: OK");
			JavaSystem.@out.println("");

			/*
			 * Round 2
			 * 
			 * Alice and Bob each generate a round 2 payload, and send it to each other.
			 */

			JPAKERound2Payload aliceRound2Payload = alice.createRound2PayloadToSend();
			JPAKERound2Payload bobRound2Payload = bob.createRound2PayloadToSend();

			JavaSystem.@out.println("************ Round 2 **************");
			JavaSystem.@out.println("Alice sends to Bob: ");
			JavaSystem.@out.println("A=" + aliceRound2Payload.getA().ToString(16));
			JavaSystem.@out.println("KP{x2*s}={" + aliceRound2Payload.getKnowledgeProofForX2s()[0].ToString(16) + "},{" + aliceRound2Payload.getKnowledgeProofForX2s()[1].ToString(16) + "}");
			JavaSystem.@out.println("");

			JavaSystem.@out.println("Bob sends to Alice");
			JavaSystem.@out.println("B=" + bobRound2Payload.getA().ToString(16));
			JavaSystem.@out.println("KP{x4*s}={" + bobRound2Payload.getKnowledgeProofForX2s()[0].ToString(16) + "},{" + bobRound2Payload.getKnowledgeProofForX2s()[1].ToString(16) + "}");
			JavaSystem.@out.println("");

			/*
			 * Each participant must then validate the received payload for round 2
			 */

			alice.validateRound2PayloadReceived(bobRound2Payload);
			JavaSystem.@out.println("Alice checks KP{x4*s}: OK\n");

			bob.validateRound2PayloadReceived(aliceRound2Payload);
			JavaSystem.@out.println("Bob checks KP{x2*s}: OK\n");

			/*
			 * After round 2, each participant computes the keying material.
			 */

			BigInteger aliceKeyingMaterial = alice.calculateKeyingMaterial();
			BigInteger bobKeyingMaterial = bob.calculateKeyingMaterial();

			JavaSystem.@out.println("********* After round 2 ***********");
			JavaSystem.@out.println("Alice computes key material \t K=" + aliceKeyingMaterial.ToString(16));
			JavaSystem.@out.println("Bob computes key material \t K=" + bobKeyingMaterial.ToString(16));
			JavaSystem.@out.println();


			/*
			 * You must derive a session key from the keying material applicable
			 * to whatever encryption algorithm you want to use.
			 */

			BigInteger aliceKey = deriveSessionKey(aliceKeyingMaterial);
			BigInteger bobKey = deriveSessionKey(bobKeyingMaterial);

			/*
			 * At this point, you can stop and use the session keys if you want.
			 * This is implicit key confirmation.
			 * 
			 * If you want to explicitly confirm that the key material matches,
			 * you can continue on and perform round 3.
			 */

			/*
			 * Round 3
			 * 
			 * Alice and Bob each generate a round 3 payload, and send it to each other.
			 */

			JPAKERound3Payload aliceRound3Payload = alice.createRound3PayloadToSend(aliceKeyingMaterial);
			JPAKERound3Payload bobRound3Payload = bob.createRound3PayloadToSend(bobKeyingMaterial);

			JavaSystem.@out.println("************ Round 3 **************");
			JavaSystem.@out.println("Alice sends to Bob: ");
			JavaSystem.@out.println("MacTag=" + aliceRound3Payload.getMacTag().ToString(16));
			JavaSystem.@out.println("");
			JavaSystem.@out.println("Bob sends to Alice: ");
			JavaSystem.@out.println("MacTag=" + bobRound3Payload.getMacTag().ToString(16));
			JavaSystem.@out.println("");

			/*
			 * Each participant must then validate the received payload for round 3
			 */

			alice.validateRound3PayloadReceived(bobRound3Payload, aliceKeyingMaterial);
			JavaSystem.@out.println("Alice checks MacTag: OK\n");

			bob.validateRound3PayloadReceived(aliceRound3Payload, bobKeyingMaterial);
			JavaSystem.@out.println("Bob checks MacTag: OK\n");

			JavaSystem.@out.println();
			JavaSystem.@out.println("MacTags validated, therefore the keying material matches.");
		}

		private static BigInteger deriveSessionKey(BigInteger keyingMaterial)
		{
			/*
			 * You should use a secure key derivation function (KDF) to derive the session key.
			 * 
			 * For the purposes of this example, I'm just going to use a hash of the keying material.
			 */
			SHA256Digest digest = new SHA256Digest();

			byte[] keyByteArray = keyingMaterial.toByteArray();

			byte[] output = new byte[digest.getDigestSize()];

			digest.update(keyByteArray, 0, keyByteArray.Length);

			digest.doFinal(output, 0);

			return new BigInteger(output);
		}
	}

}