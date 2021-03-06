﻿using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.cmc
{
	
	/// <summary>
	/// <pre>
	///   ExtensionReq ::= SEQUENCE SIZE (1..MAX) OF Extension
	/// </pre>
	/// </summary>
	public class ExtensionReq : ASN1Object
	{
		private readonly Extension[] extensions;

		public static ExtensionReq getInstance(object obj)
		{
			if (obj is ExtensionReq)
			{
				return (ExtensionReq)obj;
			}

			if (obj != null)
			{
				return new ExtensionReq(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static ExtensionReq getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

        /// <summary>
        /// Construct a ExtensionReq object containing one Extension.
        /// </summary>
        /// <param name="extension"> the Extension to be contained. </param>
        public ExtensionReq(Extension extension)
		{
			this.extensions = new Extension[]{ extension };
		}


		public ExtensionReq(Extension[] extensions)
		{
			this.extensions = Utils.clone(extensions);
		}

		private ExtensionReq(ASN1Sequence seq)
		{
			this.extensions = new Extension[seq.size()];

			for (int i = 0; i != seq.size(); i++)
			{
				extensions[i] = Extension.getInstance(seq.getObjectAt(i));
			}
		}

		public virtual Extension[] getExtensions()
		{
			return Utils.clone(extensions);
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(extensions);
		}


	}

}