using System;

namespace org.bouncycastle.x509
{

	using ErrorBundle = org.bouncycastle.i18n.ErrorBundle;
	using LocalizedException = org.bouncycastle.i18n.LocalizedException;

	public class CertPathReviewerException : LocalizedException
	{

		private int index = -1;

		private CertPath certPath = null;

		public CertPathReviewerException(ErrorBundle errorMessage, Exception throwable) : base(errorMessage, throwable)
		{
		}

		public CertPathReviewerException(ErrorBundle errorMessage) : base(errorMessage)
		{
		}

		public CertPathReviewerException(ErrorBundle errorMessage, Exception throwable, CertPath certPath, int index) : base(errorMessage, throwable)
		{
			if (certPath == null || index == -1)
			{
				throw new IllegalArgumentException();
			}
			if (index < -1 || (certPath != null && index >= certPath.getCertificates().size()))
			{
				throw new IndexOutOfBoundsException();
			}
			this.certPath = certPath;
			this.index = index;
		}

		public CertPathReviewerException(ErrorBundle errorMessage, CertPath certPath, int index) : base(errorMessage)
		{
			if (certPath == null || index == -1)
			{
				throw new IllegalArgumentException();
			}
			if (index < -1 || (certPath != null && index >= certPath.getCertificates().size()))
			{
				throw new IndexOutOfBoundsException();
			}
			this.certPath = certPath;
			this.index = index;
		}

		public virtual CertPath getCertPath()
		{
			return certPath;
		}

		public virtual int getIndex()
		{
			return index;
		}

	}

}