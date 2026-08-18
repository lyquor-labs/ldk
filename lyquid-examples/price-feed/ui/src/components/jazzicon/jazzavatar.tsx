import React, { useEffect, useMemo, useState, type ComponentProps } from 'react';


import { getMaskiconSVG } from './utils';

type MaskiconProps = Omit<ComponentProps<'img'>, 'width' | 'height'> & {
  /**
   * Required address used as a unique identifier to generate the Maskicon.
   */
  address: string;
  /**
   * Optional prop to control the size of the Maskicon.
   * This will set both width and height.
   */
  size?: number;
  /**
   * Optional CSS class name to apply to the Maskicon.
   */
  className?: string;
  /**
   * Optional prop to add a test id to the icon
   */
  'data-testid'?: string;
};

export const JazzAvatar = ({
  address,
  size = 32,
  className,
  ...props
}: MaskiconProps) => {
  const [svgString, setSvgString] = useState('');

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const newSvg = await getMaskiconSVG(address, size);
      if (!cancelled) {
        setSvgString(newSvg);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [address, size]);

  const dataUri = useMemo(() => {
    if (!svgString) {
      return '';
    }
    // Normalize whitespace and encode the SVG for safe data URI usage
    const cleanedSvg = svgString.replace(/\s+/gu, ' ').trim();
    const encoded = encodeURIComponent(cleanedSvg);
    return `data:image/svg+xml,${encoded}`;
  }, [svgString]);

  if (!dataUri) {
    // Return an img element with transparent placeholder to maintain consistent typing
    return (
      <img
        alt="maskicon"
        width={size}
        height={size}
        className={className}
        src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E"
        {...props}
      />
    );
  }

  return (
    <img
      alt="maskicon"
      width={size}
      height={size}
      className={className}
      src={dataUri}
      {...props}
    />
  );
};
