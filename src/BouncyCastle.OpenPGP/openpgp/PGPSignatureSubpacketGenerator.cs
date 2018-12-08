using org.bouncycastle.bcpg;
using org.bouncycastle.bcpg.sig;

using System;

namespace org.bouncycastle.openpgp
{

	using SignatureSubpacket = org.bouncycastle.bcpg.SignatureSubpacket;
	using SignatureSubpacketTags = org.bouncycastle.bcpg.SignatureSubpacketTags;
	using EmbeddedSignature = org.bouncycastle.bcpg.sig.EmbeddedSignature;
	using Exportable = org.bouncycastle.bcpg.sig.Exportable;
	using Features = org.bouncycastle.bcpg.sig.Features;
	using IssuerKeyID = org.bouncycastle.bcpg.sig.IssuerKeyID;
	using KeyExpirationTime = org.bouncycastle.bcpg.sig.KeyExpirationTime;
	using KeyFlags = org.bouncycastle.bcpg.sig.KeyFlags;
	using NotationData = org.bouncycastle.bcpg.sig.NotationData;
	using PreferredAlgorithms = org.bouncycastle.bcpg.sig.PreferredAlgorithms;
	using PrimaryUserID = org.bouncycastle.bcpg.sig.PrimaryUserID;
	using Revocable = org.bouncycastle.bcpg.sig.Revocable;
	using RevocationKey = org.bouncycastle.bcpg.sig.RevocationKey;
	using RevocationKeyTags = org.bouncycastle.bcpg.sig.RevocationKeyTags;
	using RevocationReason = org.bouncycastle.bcpg.sig.RevocationReason;
	using SignatureCreationTime = org.bouncycastle.bcpg.sig.SignatureCreationTime;
	using SignatureExpirationTime = org.bouncycastle.bcpg.sig.SignatureExpirationTime;
	using SignatureTarget = org.bouncycastle.bcpg.sig.SignatureTarget;
	using SignerUserID = org.bouncycastle.bcpg.sig.SignerUserID;
	using TrustSignature = org.bouncycastle.bcpg.sig.TrustSignature;

	/// <summary>
	/// Generator for signature subpackets.
	/// </summary>
	public class PGPSignatureSubpacketGenerator
	{
		internal List list = new ArrayList();

		public PGPSignatureSubpacketGenerator()
		{
		}

		public virtual void setRevocable(bool isCritical, bool isRevocable)
		{
			list.add(new Revocable(isCritical, isRevocable));
		}

		public virtual void setExportable(bool isCritical, bool isExportable)
		{
			list.add(new Exportable(isCritical, isExportable));
		}

		public virtual void setFeature(bool isCritical, byte feature)
		{
			list.add(new Features(isCritical, feature));
		}

		/// <summary>
		/// Add a TrustSignature packet to the signature. The values for depth and trust are
		/// largely installation dependent but there are some guidelines in RFC 4880 -
		/// 5.2.3.13.
		/// </summary>
		/// <param name="isCritical"> true if the packet is critical. </param>
		/// <param name="depth"> depth level. </param>
		/// <param name="trustAmount"> trust amount. </param>
		public virtual void setTrust(bool isCritical, int depth, int trustAmount)
		{
			list.add(new TrustSignature(isCritical, depth, trustAmount));
		}

		/// <summary>
		/// Set the number of seconds a key is valid for after the time of its creation. A
		/// value of zero means the key never expires.
		/// </summary>
		/// <param name="isCritical"> true if should be treated as critical, false otherwise. </param>
		/// <param name="seconds"> </param>
		public virtual void setKeyExpirationTime(bool isCritical, long seconds)
		{
			list.add(new KeyExpirationTime(isCritical, seconds));
		}

		/// <summary>
		/// Set the number of seconds a signature is valid for after the time of its creation.
		/// A value of zero means the signature never expires.
		/// </summary>
		/// <param name="isCritical"> true if should be treated as critical, false otherwise. </param>
		/// <param name="seconds"> </param>
		public virtual void setSignatureExpirationTime(bool isCritical, long seconds)
		{
			list.add(new SignatureExpirationTime(isCritical, seconds));
		}

		/// <summary>
		/// Set the creation time for the signature.
		/// <para>
		/// Note: this overrides the generation of a creation time when the signature is
		/// generated.
		/// </para>
		/// </summary>
		public virtual void setSignatureCreationTime(bool isCritical, DateTime date)
		{
			list.add(new SignatureCreationTime(isCritical, date));
		}

		public virtual void setPreferredHashAlgorithms(bool isCritical, int[] algorithms)
		{
			list.add(new PreferredAlgorithms(SignatureSubpacketTags_Fields.PREFERRED_HASH_ALGS, isCritical, algorithms));
		}

		public virtual void setPreferredSymmetricAlgorithms(bool isCritical, int[] algorithms)
		{
			list.add(new PreferredAlgorithms(SignatureSubpacketTags_Fields.PREFERRED_SYM_ALGS, isCritical, algorithms));
		}

		public virtual void setPreferredCompressionAlgorithms(bool isCritical, int[] algorithms)
		{
			list.add(new PreferredAlgorithms(SignatureSubpacketTags_Fields.PREFERRED_COMP_ALGS, isCritical, algorithms));
		}

		public virtual void setKeyFlags(bool isCritical, int flags)
		{
			list.add(new KeyFlags(isCritical, flags));
		}

		public virtual void setSignerUserID(bool isCritical, string userID)
		{
			if (string.ReferenceEquals(userID, null))
			{
				throw new IllegalArgumentException("attempt to set null SignerUserID");
			}

			list.add(new SignerUserID(isCritical, userID));
		}

		public virtual void setSignerUserID(bool isCritical, byte[] rawUserID)
		{
			if (rawUserID == null)
			{
				throw new IllegalArgumentException("attempt to set null SignerUserID");
			}

			list.add(new SignerUserID(isCritical, false, rawUserID));
		}

		public virtual void setEmbeddedSignature(bool isCritical, PGPSignature pgpSignature)
		{
			byte[] sig = pgpSignature.getEncoded();
			byte[] data;

			if (sig.Length - 1 > 256)
			{
				data = new byte[sig.Length - 3];
			}
			else
			{
				data = new byte[sig.Length - 2];
			}

			JavaSystem.arraycopy(sig, sig.Length - data.Length, data, 0, data.Length);

			list.add(new EmbeddedSignature(isCritical, false, data));
		}

		public virtual void setPrimaryUserID(bool isCritical, bool isPrimaryUserID)
		{
			list.add(new PrimaryUserID(isCritical, isPrimaryUserID));
		}

		public virtual void setNotationData(bool isCritical, bool isHumanReadable, string notationName, string notationValue)
		{
			list.add(new NotationData(isCritical, isHumanReadable, notationName, notationValue));
		}

		/// <summary>
		/// Sets revocation reason sub packet
		/// </summary>
		public virtual void setRevocationReason(bool isCritical, byte reason, string description)
		{
			list.add(new RevocationReason(isCritical, reason, description));
		}

		/// <summary>
		/// Sets revocation key sub packet
		/// </summary>
		public virtual void setRevocationKey(bool isCritical, int keyAlgorithm, byte[] fingerprint)
		{
			list.add(new RevocationKey(isCritical, RevocationKeyTags_Fields.CLASS_DEFAULT, keyAlgorithm, fingerprint));
		}

		/// <summary>
		/// Sets issuer key sub packet
		/// </summary>
		public virtual void setIssuerKeyID(bool isCritical, long keyID)
		{
			list.add(new IssuerKeyID(isCritical, keyID));
		}

		/// <summary>
		/// Sets a signature target sub packet.
		/// </summary>
		public virtual void setSignatureTarget(bool isCritical, int publicKeyAlgorithm, int hashAlgorithm, byte[] hashData)
		{
			list.add(new SignatureTarget(isCritical, publicKeyAlgorithm, hashAlgorithm, hashData));
		}

		public virtual PGPSignatureSubpacketVector generate()
		{
			return new PGPSignatureSubpacketVector((SignatureSubpacket[])list.toArray(new SignatureSubpacket[list.size()]));
		}
	}

}