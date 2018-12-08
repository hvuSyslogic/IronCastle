namespace org.bouncycastle.openpgp
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Iterable = org.bouncycastle.util.Iterable;

	/// <summary>
	/// A list of PGP signatures - normally in the signature block after literal data.
	/// </summary>
	public class PGPSignatureList : Iterable<PGPSignature>
	{
		internal PGPSignature[] sigs;

		public PGPSignatureList(PGPSignature[] sigs)
		{
			this.sigs = new PGPSignature[sigs.Length];

			JavaSystem.arraycopy(sigs, 0, this.sigs, 0, sigs.Length);
		}

		public PGPSignatureList(PGPSignature sig)
		{
			this.sigs = new PGPSignature[1];
			this.sigs[0] = sig;
		}

		public virtual PGPSignature get(int index)
		{
			return sigs[index];
		}

		public virtual int size()
		{
			return sigs.Length;
		}

		public virtual bool isEmpty()
		{
			return (sigs.Length == 0);
		}

		/// <summary>
		/// Support method for Iterable where available.
		/// </summary>
		public virtual Iterator<PGPSignature> iterator()
		{
			return new Arrays.Iterator(sigs);
		}
	}

}