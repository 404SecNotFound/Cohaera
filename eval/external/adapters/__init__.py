"""Per-corpus adapters into Cohaera's Session model.

Every adapter in this package is held to the contract in :mod:`.base`: a field
the source corpus does not carry is ABSENT from the adapted session and recorded
in an absence ledger. It is never defaulted to a value that reads as benign, as
safe, or as evidenced. :func:`.base.assert_no_fabricated_evidence` enforces that
at adapt time rather than leaving it to review.
"""
