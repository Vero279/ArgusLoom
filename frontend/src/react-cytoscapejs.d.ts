declare module 'react-cytoscapejs' {
  import type { ComponentType, CSSProperties } from 'react';
  import type cytoscape from 'cytoscape';

  interface CytoscapeComponentProps {
    elements: cytoscape.ElementDefinition[];
    stylesheet: cytoscape.StylesheetJson;
    layout: cytoscape.LayoutOptions;
    cy?: (instance: cytoscape.Core) => void;
    style?: CSSProperties;
    className?: string;
    minZoom?: number;
    maxZoom?: number;
    userZoomingEnabled?: boolean;
    userPanningEnabled?: boolean;
  }

  const CytoscapeComponent: ComponentType<CytoscapeComponentProps>;
  export default CytoscapeComponent;
}
